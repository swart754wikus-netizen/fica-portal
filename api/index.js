// Vercel serverless entry: every request is routed here (see vercel.json) and handled by
// the same Express app as local development, backed by Firestore + Firebase Storage.
import { config } from '../src/config.js';
import { createStore } from '../src/store/index.js';
import { createApp } from '../src/app.js';

const app = createApp({ store: await createStore(config), config });
export default app;
