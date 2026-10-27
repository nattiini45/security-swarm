"use strict";

/**
 * Wrap an async route handler so a rejected promise reaches Express' error
 * handler instead of becoming an unhandled rejection that can terminate the
 * process.
 * @param {(req: any, res: any, next: any) => Promise<any>} fn
 * @returns {(req: any, res: any, next: any) => void}
 */
function asyncHandler(fn) {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

module.exports = { asyncHandler };
