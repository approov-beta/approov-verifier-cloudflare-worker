// Keep the command name; preflight shares the runtime validator.
import('./preflight.mjs').then(({ validateConfig }) => {
  validateConfig(process.argv.slice(2))
  console.log('Approov configuration is valid')
}).catch(err => {
  console.error(err.message)
  process.exitCode = 1
})
