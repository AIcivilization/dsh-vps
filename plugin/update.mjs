// plugin/update.mjs — 插件自己的版本与更新（设置 → VPS 部署 右上角）
//
// 做法与 dsh-vps-manager 一致：查 npm 上的最新版（官方源连不上就问镜像），点「更新」交给 DSH
// 自己的插件管理器（pluginManager 服务：带锁跑 pnpm，失败自动还原 profile）装那个精确版本，
// 装好后重启 DSH 生效。查询结果在内存里存 6 小时，点「检查更新」时马上重查。

import { readFile } from 'node:fs/promises'
import { createRequire } from 'node:module'

const require = createRequire(import.meta.url)
// 启动时加载的版本；磁盘上的可能更新（装了新版还没重启）
const LOADED_VERSION = require('../package.json').version

export const PACKAGE = 'dsh-vps'
const NPM_REGISTRIES = ['https://registry.npmjs.org', 'https://registry.npmmirror.com']
const CHECK_EVERY_MS = 6 * 60 * 60 * 1000
const FETCH_TIMEOUT_MS = 6000
const VERSION_RE = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/

/** 比较 x.y.z(-pre)：a 新返回正数；同一个 x.y.z 时正式版比预发布版新 */
export function compareVersions(a, b) {
  const parse = (v) => {
    const [core, pre = ''] = String(v ?? '').replace(/^v/, '').split('-', 2)
    return { nums: core.split('.').map((n) => Number.parseInt(n, 10) || 0), pre }
  }
  const x = parse(a)
  const y = parse(b)
  for (let i = 0; i < 3; i++) {
    const d = (x.nums[i] ?? 0) - (y.nums[i] ?? 0)
    if (d) return d
  }
  if (x.pre === y.pre) return 0
  if (!x.pre) return 1
  if (!y.pre) return -1
  return x.pre < y.pre ? -1 : 1
}

async function latestOnNpm(fetchImpl) {
  let last
  for (const registry of NPM_REGISTRIES) {
    try {
      const res = await fetchImpl(`${registry}/${PACKAGE}/latest`, {
        headers: { accept: 'application/json', 'user-agent': `${PACKAGE}/${LOADED_VERSION}` },
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data = await res.json()
      if (VERSION_RE.test(String(data?.version ?? ''))) return { version: data.version, registry }
    } catch (error) {
      last = error
    }
  }
  throw last ?? new Error('no registry answered')
}

/** 磁盘上现在装的版本（不走 require 缓存：装了新版、还没重启时它比 LOADED_VERSION 新） */
async function installedVersion() {
  try {
    return JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8')).version ?? ''
  } catch {
    return ''
  }
}

let cache = null // { checkedAt, npm: { version, registry } }

/** 有没有新版本。默认用 6 小时内查过的结果；force 时马上重查。网络不通不报错，只标出 offline。 */
export async function checkUpdate({ force = false, fetchImpl = globalThis.fetch, now = Date.now, running = LOADED_VERSION } = {}) {
  let offline = false
  if (force || !cache || now() - cache.checkedAt > CHECK_EVERY_MS) {
    try {
      cache = { checkedAt: now(), npm: await latestOnNpm(fetchImpl) }
    } catch {
      offline = true
    }
  }
  const disk = await installedVersion()
  const restartPending = disk && compareVersions(disk, running) > 0 ? disk : ''
  const current = restartPending || running
  const latest = cache?.npm?.version || ''
  const installable = latest && compareVersions(latest, current) > 0 ? latest : ''
  return {
    running,
    restartPending,
    latest,
    available: Boolean(installable),
    installable,
    checkedAt: cache?.checkedAt ?? null,
    offline,
    command: `dsh plugin add ${PACKAGE}@${installable || latest || 'latest'}`,
  }
}

/** 装新版：交给 DSH 的插件管理器；已装着的包换了版本要重启 DSH 才生效 */
export async function runUpdate({ pluginManager, version, running = LOADED_VERSION }) {
  if (!VERSION_RE.test(String(version ?? ''))) return { ok: false, code: 'invalid-spec' }
  if (compareVersions(version, running) <= 0) return { ok: false, code: 'not-newer' }
  if (typeof pluginManager?.installBundle !== 'function') {
    return { ok: false, code: 'no-manager', command: `dsh plugin add ${PACKAGE}@${version}` }
  }
  const result = await pluginManager.installBundle(`${PACKAGE}@${version}`, { enabled: true })
  if (result?.application === 'failed' || result?.application === 'cancelled' || result?.error) {
    const code = result?.error?.code ?? result?.application ?? 'failed'
    const detail = String(result?.error?.diagnostic ?? result?.packageResult?.output ?? '').trim().split('\n').slice(-6).join('\n').slice(-800)
    return { ok: false, code, detail, command: `dsh plugin add ${PACKAGE}@${version}` }
  }
  return { ok: true, version }
}
