// Fixed-window limiter backed by the store, so it holds across serverless instances.
export function rateLimit(store, { windowMs, max, key = (req) => req.ip, name = 'rl' }) {
  return async (req, res, next) => {
    try {
      const { count, reset } = await store.rateHit(`${name}:${key(req)}`, windowMs);
      if (count > max) {
        res.set('Retry-After', String(Math.ceil((reset - Date.now()) / 1000)));
        return res.status(429).send('Too many attempts. Please wait and try again.');
      }
      next();
    } catch (err) { next(err); }
  };
}
