export type Keypair = { signPub: string; signSec: string; boxPub: string; boxSec: string };
export type PublicIdentity = { id: string; signPub: string; boxPub: string };
/** `task` opens a thread, `message` is a turn inside it in either direction, `result` closes it. */
export type Kind = 'task' | 'message' | 'result' | 'status';
export type Inner = {
  v: 1;
  kind: Kind;
  taskId: string;
  seq: number;
  from: string;
  /** Session (process) of the sender; replies are addressed to it. */
  fromSession: string;
  to: string;
  session: string;
  body: string;
  status?: 'queued' | 'running' | 'held' | 'rejected' | 'done';
  ts: number;
};
export type Outer = { from: string; fromSession: string; to: string; session: string; ct: string };
