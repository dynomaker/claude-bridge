import { launchHook, readFd0 } from './hook-launch.js';

let wrote = false;
await launchHook({
  readStdin: readFd0,
  importHook: () => import('./hook.js'),
  env: process.env,
  write: (s) => {
    wrote = true;
    // Exit once flushed so stray handles (e.g. classifier subprocesses) cannot keep the hook alive.
    process.stdout.write(s, () => process.exit(0));
  },
});
if (!wrote) process.exit(0);
