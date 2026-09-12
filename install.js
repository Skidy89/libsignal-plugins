const { createWriteStream, existsSync, readFileSync, renameSync, unlinkSync } = require('fs')
const { join } = require('path')
const { pipeline } = require('stream/promises')

const packageJson = JSON.parse(readFileSync(join(__dirname, 'package.json'), 'utf8'))
const binaryName = getBinaryName()

if (binaryName && !existsSync(join(__dirname, binaryName))) {
  installBinary(binaryName).catch((error) => {
    console.error(`Unable to install the native binding for ${process.platform}-${process.arch}.`)
    console.error(error.message)
    process.exitCode = 1
  })
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

async function installBinary(name) {
  const releaseTag = `v${packageJson.version}`
  const url = `https://github.com/Skidy89/libsignal-plugins/releases/download/${releaseTag}/${name}`
  const temporaryPath = join(__dirname, `.download-${process.pid}-${name}`)
  const response = await fetch(url)

  if (!response.ok || !response.body) {
    throw new Error(`GitHub Release ${releaseTag} does not contain ${name} (HTTP ${response.status}).`)
  }

  try {
    await pipeline(response.body, createWriteStream(temporaryPath))
    renameSync(temporaryPath, join(__dirname, name))
  } finally {
    if (existsSync(temporaryPath)) {
      unlinkSync(temporaryPath)
    }
  }
}