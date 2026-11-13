import { existsSync, readFileSync } from 'node:fs'
import { resolve, dirname } from 'node:path'
import { unstable_readConfig as readConfig, unstable_getVarsForDev as getVarsForDev } from 'wrangler'
import { build } from 'esbuild'
import { fileURLToPath } from 'node:url'
import { assertValidConfig } from '../src/config/schema.mjs'
import { generatePluginRegistry } from './generate-plugins.mjs'

// Bundle the same runtime validator in memory, including plugin JSON imports.
const bundle = await build({
  entryPoints: [fileURLToPath(new URL('../src/config/context.js', import.meta.url))],
  bundle: true,
  write: false,
  format: 'esm',
  platform: 'node',
  external: ['node:*'],
  plugins: [{
    name: 'current-plugin-registry',
    setup (compiler) {
      compiler.onLoad({ filter: /plugins\.generated\.js$/ }, () => ({
        contents: generatePluginRegistry().content,
        loader: 'js',
        resolveDir: fileURLToPath(new URL('../src', import.meta.url))
      }))
    }
  }]
})
const { establishContext } = await import(`data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].text).toString('base64')}`)

// Preserve Wrangler's arguments for execution; extract only binding inputs.
export const configArguments = (argv) => {
  const args = { vars: {}, envFiles: [] }
  for (let i = 0; i < argv.length; i++) {
    const [flag, inline] = argv[i].split(/=(.*)/s)
    const take = () => inline === undefined ? argv[++i] : inline
    const takeMany = () => {
      const entries = [take()]
      while (argv[i + 1] && !argv[i + 1].startsWith('-')) entries.push(argv[++i])
      return entries
    }
    if (['--config', '-c'].includes(flag)) args.config = take()
    else if (['--env', '-e'].includes(flag)) args.env = take()
    else if (flag === '--env-file') args.envFiles.push(...takeMany())
    else if (flag === '--secrets-file') args.secretsFile = take()
    else if (flag === '--cwd') args.cwd = take()
    else if (flag === '--var') {
      for (const entry of takeMany()) {
        const colon = entry?.indexOf(':') ?? -1
        if (colon <= 0) throw new Error('--var must use NAME:value')
        args.vars[entry.slice(0, colon)] = entry.slice(colon + 1)
      }
    }
  }
  return args
}

export const validateConfig = (argv, { development = false } = {}) => {
  const args = configArguments(argv)
  const oldCwd = process.cwd()
  try {
    if (args.cwd) process.chdir(resolve(args.cwd))
    const config = readConfig({ config: args.config, env: args.env }, { hideWarnings: true })
    // Wrangler resolves explicit CLI env files from its effective command
    // directory. getVarsForDev instead resolves relative paths beside config.
    const envFiles = args.envFiles.map(file => resolve(file))
    let bindings = { ...config.vars }
    if (development) {
      bindings = Object.fromEntries(Object.entries(getVarsForDev(
        config.configPath, envFiles.length ? envFiles : undefined,
        bindings, args.env, true, config.secrets
      )).map(([name, binding]) => [name, binding.value]))
    }
    if (args.secretsFile) {
      const file = resolve(args.secretsFile)
      let secrets
      try { secrets = JSON.parse(readFileSync(file, 'utf8')) } catch {
        secrets = Object.fromEntries(Object.entries(getVarsForDev(
          config.configPath, [file], {}, undefined, true
        )).map(([name, binding]) => [name, binding.value]))
      }
      bindings = { ...bindings, ...secrets }
    }
    Object.assign(bindings, args.vars)
    for (const dataset of config.analytics_engine_datasets || []) {
      bindings[dataset.binding] = { writeDataPoint () {} }
    }
    const exportPath = resolve(dirname(config.configPath || 'wrangler.toml'), 'approov-config.json')
    if (!Object.hasOwn(bindings, 'APPROOV_BACKEND_CONFIG') && existsSync(exportPath)) {
      bindings.APPROOV_BACKEND_CONFIG = readFileSync(exportPath, 'utf8')
    }
    const context = establishContext(bindings, { preflight: !development })
    assertValidConfig(context)
    return context
  } finally {
    process.chdir(oldCwd)
  }
}
