// plugin/remote-install.mjs — 从这台 DSH 经 SSH 把 dsh-vps 装到（或卸出）指定的 VPS
//
// 设置 → VPS 部署 的表单填好服务器信息后调用；action 为 install 或 uninstall。要点：
//   - 登录方式三选一：密码 / 粘贴的私钥 / 本机密钥。密码（或私钥口令）只进这一次 ssh 子进程的
//     环境变量，经 SSH_ASKPASS 小脚本交给 ssh：不写盘、不进日志、不保存（与 dsh-vps-manager
//     「添加机器」同一做法）。粘贴的私钥写进 0600 临时文件只给这一次 ssh 用，结束即删
//   - 本机密钥：~/.ssh 里已有的，加上本插件专用的一把（界面上一键生成，复制公钥加到服务器上）
//   - 安装在服务器上以 nohup + setsid 后台运行，日志写 /var/log/dsh-vps-install.log；
//     这边只是 tail 它。SSH 中途断开，安装照样跑完
//   - 同一时间只跑一个安装任务；结果（含带一次性令牌的设置链接）留在内存里供界面轮询
//
// 路由挂在 DSH 的 /api 通道（ctx.connection.fetch），由 DSH 自己做同源与登录校验。

import { spawn } from 'node:child_process'
import { existsSync } from 'node:fs'
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { homedir, hostname, tmpdir } from 'node:os'
import { join } from 'node:path'
import { StringDecoder } from 'node:string_decoder'

const RAW_BASE = 'https://raw.githubusercontent.com/AIcivilization/dsh-vps/main'
const ACTIONS = {
  install: { script: `${RAW_BASE}/install.sh`, log: '/var/log/dsh-vps-install.log' },
  uninstall: { script: `${RAW_BASE}/uninstall.sh`, log: '/var/log/dsh-vps-uninstall.log' },
}
const JOB_TIMEOUT_MS = 40 * 60_000
const MAX_LINES = 400

const HOST_RE = /^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*|\[?[0-9A-Fa-f:.]+\]?)$/
const DOMAIN_RE = /^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$/
const USER_RE = /^[A-Za-z_][A-Za-z0-9_.-]{0,31}$/
const AUTHS = new Set(['password', 'key', 'local'])
const PRIVATE_KEY_RE = /^-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----\n[\s\S]+\n-----END [A-Z0-9 ]*PRIVATE KEY-----\n$/

/** 粘贴来的私钥：统一换行、去首尾空白、补上结尾换行（ssh 读私钥要求以换行结束） */
export function normalizePrivateKey(text) {
  const trimmed = String(text ?? '').replace(/\r\n?/g, '\n').trim()
  return trimmed ? `${trimmed}\n` : ''
}

/** 校验并规整表单；返回 { value } 或 { error }（界面直接展示 error） */
export function validateRequest(body) {
  const b = body && typeof body === 'object' ? body : {}
  const host = String(b.host ?? '').trim().replace(/^\[|\]$/g, '')
  const port = Number(b.port ?? 22)
  const user = String(b.user ?? 'root').trim() || 'root'
  const password = typeof b.password === 'string' ? b.password : ''
  const privateKey = normalizePrivateKey(typeof b.privateKey === 'string' ? b.privateKey : '')
  const passphrase = typeof b.passphrase === 'string' ? b.passphrase : ''
  // 旧版界面只传 password：填了用密码，留空用本机密钥
  const auth = AUTHS.has(b.auth) ? b.auth : password ? 'password' : 'local'
  const action = b.action === 'uninstall' ? 'uninstall' : 'install'
  const domain = action === 'install' ? String(b.domain ?? '').trim().toLowerCase() : ''
  const mirror = action === 'install' && b.mirror === true
  // 卸载默认保留 DSH 数据（对话、设置）：不勾才删
  const keepData = action === 'uninstall' && b.keepData !== false
  const purgeCaddy = action === 'uninstall' && b.purgeCaddy === true
  if (!host || host.length > 253 || !HOST_RE.test(host)) return { error: '服务器地址格式不对（填公网 IP 或能解析到它的域名）' }
  if (!Number.isInteger(port) || port < 1 || port > 65535) return { error: 'SSH 端口应为 1–65535' }
  if (!USER_RE.test(user)) return { error: '用户名格式不对' }
  if (password.length > 1024 || passphrase.length > 1024) return { error: '密码太长' }
  if (auth === 'password' && !password) return { error: '请填写服务器的登录密码' }
  if (auth === 'key') {
    if (!privateKey) return { error: '请粘贴私钥（或选择私钥文件）' }
    if (privateKey.length > 32 * 1024 || !PRIVATE_KEY_RE.test(privateKey)) {
      return { error: '私钥格式不对：应是以 -----BEGIN … PRIVATE KEY----- 开头的完整文件内容（.pem / id_ed25519 等）。PuTTY 的 .ppk 要先用 PuTTYgen 导出为 OpenSSH 格式' }
    }
  }
  if (domain && (domain.length > 253 || !DOMAIN_RE.test(domain))) return { error: '访问域名格式不对（例如 dsh.example.com）' }
  return {
    value: {
      action, host, port, user, auth,
      password: auth === 'password' ? password : '',
      privateKey: auth === 'key' ? privateKey : '',
      passphrase: auth === 'key' ? passphrase : '',
      domain, mirror, keepData, purgeCaddy,
    },
  }
}

/** 传给 install.sh / uninstall.sh 的参数 */
export function scriptArgs({ action = 'install', domain, mirror, keepData, purgeCaddy }) {
  if (action === 'uninstall') return ['--yes', ...(keepData ? ['--keep-data'] : []), ...(purgeCaddy ? ['--purge-caddy'] : [])]
  return [...(domain ? ['--domain', domain] : []), ...(mirror ? ['--mirror', 'cn'] : [])]
}

/** 服务器上执行的脚本（经 stdin 交给 sh -s，参数不进命令行） */
export function remoteScript(opts) {
  const { script, log } = ACTIONS[opts.action === 'uninstall' ? 'uninstall' : 'install']
  const args = scriptArgs(opts)
  // 参数已按正则校验（仅字母数字、点、横线），这里仍逐个单引号包起来
  const quoted = args.map((a) => `'${a.replace(/'/g, `'\\''`)}'`).join(' ')
  return [
    'set -u',
    'if [ "$(id -u)" = 0 ]; then SUDO=""; else SUDO="sudo -n"; $SUDO true 2>/dev/null || { echo "DSHVPS_ERR=need_root"; exit 3; }; fi',
    'if command -v curl >/dev/null 2>&1; then FETCH="curl -fsSL"; elif command -v wget >/dev/null 2>&1; then FETCH="wget -qO-"; else echo "DSHVPS_ERR=no_fetch"; exit 4; fi',
    `L=${log}`,
    '$SUDO rm -f "$L"',
    // 后台独立运行：SSH 断开不影响安装/卸载；结束时在日志末尾写退出码
    `$SUDO nohup setsid sh -c 'L="$1"; F="$2"; U="$3"; shift 3; { $F "$U" | bash -s -- "$@"; echo "DSHVPS_EXIT=$?"; } >>"$L" 2>&1' dshvps "$L" "$FETCH" '${script}' ${quoted} </dev/null >/dev/null 2>&1 &`,
    'P=$!',
    'for i in 1 2 3 4 5 6 7 8 9 10; do [ -f "$L" ] && break; sleep 1; done',
    'echo "DSHVPS_STARTED"',
    '$SUDO tail -n +1 -f --pid="$P" "$L" 2>/dev/null',
    '$SUDO tail -n 3 "$L" 2>/dev/null | grep "^DSHVPS_EXIT=" || true',
  ].join('\n') + '\n'
}

const strip = (s) => String(s).replace(/\x1b\[[0-9;]*m/g, '').replace(/\r/g, '')

/** 从安装输出里取带令牌的设置链接（install.sh 结尾打印「访问地址  : https://…/setup?token=…」） */
export function findSetupUrl(text) {
  const m = /https:\/\/[^\s]+\/setup\?token=[A-Za-z0-9]+/.exec(text)
  if (m) return m[0]
  const a = /访问地址\s*:\s*(https:\/\/\S+)/.exec(text)
  return a ? a[1] : null
}

/** 卸载输出里的备份位置（uninstall.sh 结尾打印「备份：/root/dsh-vps-uninstall-….tar.gz」） */
export function findBackupPath(text) {
  const m = /备份[：:]\s*(\/\S+\.tar\.gz)/.exec(text)
  return m ? m[1] : null
}

/** 本机找不到 ssh 时告诉用户怎么装（与 dsh-vps-manager 同一说法） */
export function noSshClientHint(platform = process.platform) {
  return platform === 'win32'
    ? '本机找不到 ssh 命令：打开 Windows「设置 → 系统 → 可选功能」，添加「OpenSSH 客户端」，装好后重启 DSH'
    : '本机找不到 ssh 命令：先装 OpenSSH 客户端，装好后重启 DSH'
}

// ——— 本机密钥：本插件专用的一把，放在 DSH 数据目录里，不碰用户的 ~/.ssh ———

export function localKeyPath(env = process.env) {
  return join(env.DSH_HOME || join(homedir(), '.dsh'), 'dsh-vps', 'ssh', 'id_ed25519')
}

/** ~/.ssh 里 ssh 默认会试的私钥（显式传 -i 后 ssh 不再自动加默认私钥，所以要一并列出） */
function defaultIdentities() {
  return ['id_ed25519', 'id_ecdsa', 'id_rsa'].map((n) => join(homedir(), '.ssh', n)).filter((f) => existsSync(f))
}

/** 本机专用公钥：{ publicKey } 或 { publicKey: null }（还没生成） */
export async function readLocalKey(env = process.env) {
  try {
    const publicKey = (await readFile(`${localKeyPath(env)}.pub`, 'utf8')).trim()
    return { publicKey: publicKey || null, path: localKeyPath(env) }
  } catch {
    return { publicKey: null, path: localKeyPath(env) }
  }
}

/** 生成本机专用密钥（ed25519、无口令）；已有则直接返回 */
export async function generateLocalKey({ env = process.env, spawnImpl = spawn, platform = process.platform } = {}) {
  const existing = await readLocalKey(env)
  if (existing.publicKey) return existing
  const file = localKeyPath(env)
  await mkdir(join(file, '..'), { recursive: true, mode: 0o700 })
  const comment = `dsh-vps@${hostname().replace(/[^A-Za-z0-9_.-]/g, '') || 'dsh'}`
  const result = await new Promise((resolve) => {
    let err = ''
    let child
    try {
      child = spawnImpl('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-C', comment, '-f', file], { stdio: ['ignore', 'ignore', 'pipe'], windowsHide: true })
    } catch (error) {
      resolve({ error })
      return
    }
    child.stderr.on('data', (d) => { err += d })
    child.on('error', (error) => resolve({ error }))
    child.on('close', (code) => resolve(code === 0 ? {} : { error: new Error(err.trim() || `ssh-keygen 退出码 ${code}`) }))
  })
  if (result.error) {
    const msg = /ENOENT/.test(String(result.error.message)) ? noSshClientHint(platform) : `生成密钥失败：${result.error.message}`
    return { publicKey: null, path: file, error: msg }
  }
  return readLocalKey(env)
}

/** ssh 失败说人话。auth：password | key | local（旧调用传布尔值：true 当作 password） */
export function classifyFailure(stderr, exitCode, auth, platform = process.platform) {
  const t = String(stderr)
  const mode = auth === true ? 'password' : auth === false || auth == null ? 'local' : auth
  if (/\bENOENT\b/.test(t)) return noSshClientHint(platform)
  if (/Host key verification failed|REMOTE HOST IDENTIFICATION HAS CHANGED/i.test(t)) {
    return '服务器的 SSH 指纹和本机记录的不一致（重装过系统？）。确认无误后在本机执行 ssh-keygen -R <服务器地址> 再试'
  }
  if (/incorrect passphrase|bad passphrase/i.test(t)) return '私钥口令不对'
  if (/invalid format|error in libcrypto|not a valid key/i.test(t)) return '私钥读不了：确认粘贴的是完整的私钥文件内容；PuTTY 的 .ppk 要先用 PuTTYgen 导出为 OpenSSH 格式'
  if (/Permission denied/i.test(t)) {
    if (mode === 'password') {
      return /Permission denied \(publickey\)/i.test(t)
        ? '这台服务器关掉了密码登录，只认密钥：把「登录方式」换成「私钥」（粘贴云厂商给的 .pem 私钥），或「本机密钥」（先把本机公钥加到服务器上）'
        : '密码不对，或这个用户不允许用密码登录（有的系统默认禁止 root 密码登录）'
    }
    if (mode === 'key') return '这把私钥登录不了：确认它对应的公钥在服务器上，用户名也对（有的系统镜像默认用户是 ubuntu、debian 或 admin，不是 root）；私钥设过口令的，确认口令填对了'
    return '本机的密钥登录不了这台服务器：先把「本机密钥」里的公钥加到服务器上，或改用密码 / 私钥登录'
  }
  if (/Could not resolve hostname/i.test(t)) return '服务器地址解析不了，检查一下是否填错'
  if (/Connection closed by|Connection reset by|kex_exchange_identification/i.test(t)) {
    return '服务器断开了 SSH 连接：确认端口确实是 SSH 端口，以及服务器防火墙、fail2ban 是否拦截了本机的地址'
  }
  if (/Connection refused/i.test(t)) return 'SSH 端口拒绝连接：检查端口号，以及服务器防火墙/安全组是否放行'
  if (/timed out|No route to host|Network is unreachable/i.test(t)) return '连不上服务器：检查地址和端口，以及云厂商安全组是否放行 SSH'
  if (exitCode === 3) return '这个用户不是 root，也没有免密 sudo。请改用 root，或先给该用户配置免密 sudo'
  if (exitCode === 4) return '服务器上既没有 curl 也没有 wget，先装上其中一个再试'
  const last = t.replace(/\r/g, '').trim().split('\n').filter((l) => l && !/^Warning: Permanently added/i.test(l)).pop()
  return last ? `SSH 连接失败：${last}` : `SSH 连接失败（退出码 ${exitCode}）`
}

/** 安装任务：同一时间只有一个 */
export function createInstaller({ spawnImpl = spawn, platform = process.platform, env = process.env, now = Date.now } = {}) {
  let job = null

  function snapshot() {
    if (!job) return { job: null }
    const { child, timer, ...rest } = job
    return { job: { ...rest, lines: job.lines.slice(-MAX_LINES) } }
  }

  async function start(value) {
    if (job && job.state === 'running') return { error: '已经有一个任务在进行中，等它结束再试', status: 409 }
    const { host, port, user, password, privateKey, passphrase, domain, mirror, keepData, purgeCaddy } = value
    const auth = AUTHS.has(value.auth) ? value.auth : password ? 'password' : 'local'
    const action = value.action === 'uninstall' ? 'uninstall' : 'install'
    const remoteLog = ACTIONS[action].log
    const verb = action === 'uninstall' ? '卸载' : '安装'
    job = {
      action, state: 'running', host, port, user, auth, domain, mirror, keepData, purgeCaddy,
      startedAt: now(), endedAt: null, lines: [], setupUrl: null, backupPath: null, error: null, phase: 'connecting',
    }
    const current = job
    const target = `${user}@${host.includes(':') ? `[${host}]` : host}`
    const args = [
      '-T', '-p', String(port),
      '-o', 'StrictHostKeyChecking=accept-new',
      '-o', 'ConnectTimeout=15',
      '-o', 'ServerAliveInterval=15',
      '-o', 'ServerAliveCountMax=8',
      '-o', 'ControlMaster=no',
      '-o', 'ControlPath=none',
      // 不压低日志级别：「Connection closed」「timed out」这类关键原因是 INFO 级，压到 ERROR 就只剩退出码 255
    ]
    let askDir = null
    const childEnv = { ...env }
    // 要交给 ssh 的口令：密码登录的密码，或加密私钥的口令
    const secret = auth === 'password' ? password : auth === 'key' ? passphrase : ''
    if (secret || auth === 'key') askDir = await mkdtemp(join(tmpdir(), 'dsh-vps-ssh-'))
    if (secret) {
      const helper = join(askDir, platform === 'win32' ? 'askpass.cmd' : 'askpass.sh')
      if (platform === 'win32') {
        await writeFile(helper, `@set ELECTRON_RUN_AS_NODE=1\r\n@"${process.execPath}" -e "process.stdout.write(process.env.DSH_VPS_PW+'\\n')"\r\n`)
      } else {
        await writeFile(helper, '#!/bin/sh\nprintf \'%s\\n\' "$DSH_VPS_PW"\n', { mode: 0o700 })
      }
      args.push('-o', 'NumberOfPasswordPrompts=1')
      Object.assign(childEnv, { SSH_ASKPASS: helper, SSH_ASKPASS_REQUIRE: 'force', DISPLAY: env.DISPLAY || ':0', DSH_VPS_PW: secret })
    } else {
      args.push('-o', 'BatchMode=yes')
    }
    if (auth === 'password') {
      args.push('-o', 'PreferredAuthentications=keyboard-interactive,password', '-o', 'PubkeyAuthentication=no')
    } else if (auth === 'key') {
      const keyFile = join(askDir, 'id_key')
      await writeFile(keyFile, privateKey, { mode: 0o600 })
      args.push('-i', keyFile, '-o', 'IdentitiesOnly=yes', '-o', 'PreferredAuthentications=publickey')
    } else {
      // 本机密钥：本插件专用的那把 + ~/.ssh 里的默认私钥（ssh-agent 里的也照样会试）
      for (const f of [localKeyPath(env), ...defaultIdentities()]) if (existsSync(f)) args.push('-i', f)
      args.push('-o', 'PreferredAuthentications=publickey')
    }
    args.push('--', target, 'sh -s')

    let child
    try {
      // windowsHide：Windows 上的 DSH（含桌面版）启动 ssh 时不弹控制台窗口
      child = spawnImpl('ssh', args, { env: childEnv, stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true })
    } catch (error) {
      if (askDir) rm(askDir, { recursive: true, force: true }).catch(() => {})
      current.state = 'failed'
      current.error = /ENOENT/.test(String(error.message)) ? noSshClientHint(platform) : `无法启动 ssh：${error.message}`
      current.endedAt = now()
      return { job: snapshot().job }
    }
    current.child = child
    let stderr = ''
    let buf = ''
    // 按完整字符解码：汉字可能被切在两个数据块之间
    const outDec = new StringDecoder('utf8')
    const errDec = new StringDecoder('utf8')
    const push = (line) => {
      const clean = strip(line)
      if (clean === 'DSHVPS_STARTED') {
        current.phase = 'installing'
        return
      }
      current.lines.push(clean)
      if (current.lines.length > MAX_LINES * 2) current.lines.splice(0, current.lines.length - MAX_LINES)
      if (action === 'install' && !current.setupUrl) current.setupUrl = findSetupUrl(clean)
      if (action === 'uninstall' && !current.backupPath) current.backupPath = findBackupPath(clean)
    }
    child.stdout.on('data', (d) => {
      buf += outDec.write(d)
      const parts = buf.split('\n')
      buf = parts.pop()
      for (const p of parts) push(p)
    })
    child.stderr.on('data', (d) => {
      stderr = (stderr + errDec.write(d)).slice(-4000)
    })
    const finish = (code) => {
      if (current.endedAt) return
      clearTimeout(current.timer)
      if (buf) push(buf)
      if (askDir) rm(askDir, { recursive: true, force: true }).catch(() => {})
      current.endedAt = now()
      const exitLine = current.lines.find((l) => /^DSHVPS_EXIT=\d+/.test(l))
      current.lines = current.lines.filter((l) => !/^DSHVPS_(EXIT|ERR)=/.test(l))
      const remoteExit = exitLine ? Number(exitLine.split('=')[1]) : null
      if (remoteExit === 0) {
        current.state = 'success'
      } else if (remoteExit !== null) {
        current.state = 'failed'
        current.error = `${verb}脚本执行失败（退出码 ${remoteExit}），详见下方日志；服务器上的完整日志：${remoteLog}`
      } else if (current.phase === 'installing') {
        current.state = 'failed'
        current.error = action === 'uninstall'
          ? `与服务器的连接中断了，但卸载仍在服务器上继续运行。稍后 SSH 登录执行 sudo tail -n 50 ${remoteLog} 查看结果`
          : `与服务器的连接中断了，但安装仍在服务器上继续运行。稍后 SSH 登录执行 sudo tail -n 50 ${remoteLog} 查看结果，或执行 sudo dsh-vps setup-url 取设置链接`
      } else {
        current.state = 'failed'
        current.error = classifyFailure(stderr, code, auth, platform)
      }
    }
    child.on('error', (error) => {
      stderr += `\n${error.message}`
      finish(255)
    })
    child.on('close', (code) => finish(code))
    current.timer = setTimeout(() => {
      try {
        child.kill('SIGTERM')
      } catch {
        // 已退出
      }
    }, JOB_TIMEOUT_MS)
    child.stdin.end(remoteScript({ action, domain, mirror, keepData, purgeCaddy }))
    return { job: snapshot().job }
  }

  function dispose() {
    if (job?.child && !job.endedAt) {
      try {
        job.child.kill('SIGTERM')
      } catch {
        // 已退出
      }
    }
  }

  return { start, snapshot, dispose }
}
