const { existsSync } = require('fs')
const { join } = require('path')
const { spawnSync } = require('child_process')

const packageRoot = __dirname
const nativeBinding = join(packageRoot, getBinaryName())

if (!existsSync(nativeBinding)) {
  const napiCommand = process.platform === 'win32' ? 'napi.cmd' : 'napi'
  const result = spawnSync(napiCommand, ['build', '--platform', '--release'], {
    cwd: packageRoot,
    stdio: 'inherit',
    shell: false,
  })

  if (result.error) {
    throw new Error(`Unable to build the native binding. Install Rust and Node.js build tools first: ${result.error.message}`)
  }

  if (result.status !== 0) {
    process.exit(result.status ?? 1)
  }
}

function getBinaryName() {
  if (process.platform === 'win32' && process.arch === 'x64') {
    return 'libsignal-plugins.win32-x64-msvc.node'
  }

  if (process.platform === 'linux' && process.arch === 'x64') {
    return `libsignal-plugins.linux-x64-${isMusl() ? 'musl' : 'gnu'}.node`
  }

  if (process.platform === 'linux' && process.arch === 'arm64') {
    return `libsignal-plugins.linux-arm64-${isMusl() ? 'musl' : 'gnu'}.node`
  }

  throw new Error(`Unsupported platform: ${process.platform}-${process.arch}`)
}

function isMusl() {
  try {
    const report = process.report?.getReport?.()
    return !report?.header?.glibcVersionRuntime
  } catch {
    return false
  }
}