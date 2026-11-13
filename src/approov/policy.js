// Verification results describe the request. Actions decide enforcement.
export const assessProtection = (result) => ({
  token: result.tokenResult !== 'PASS',
  binding: !['VALID', 'DISABLED'].includes(result.bindingResult),
  messageSigning: !['VALID', 'NOT_REQUIRED'].includes(result.messageSigningResult)
})

export const shouldBlock = (ctx, failures) => ctx.approovMode === 'block' &&
  Object.entries(failures).some(([layer, failed]) => failed && ctx.approovActions[layer] === 'block')
