import { Store } from './store.js';

const [cmd, name] = process.argv.slice(2);
if ((cmd !== 'invite' && cmd !== 'revoke') || !name) {
  console.error('usage: admin <invite|revoke> <name>');
  process.exit(2);
}
const store = new Store(process.env.DB_PATH ?? '/data/relay.db');
try {
  if (cmd === 'invite') console.log(store.createInvite(name));
  else {
    store.revokeIdentity(name);
    console.log(`revoked ${name}`);
  }
} finally {
  store.close();
}
