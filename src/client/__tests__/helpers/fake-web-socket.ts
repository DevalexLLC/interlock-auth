import type { WebSocketPort } from "../../types.js";

export class FakeWebSocket implements WebSocketPort {
  static instances: FakeWebSocket[] = [];
  readyState = 0;
  onopen: WebSocketPort["onopen"] = null;
  onclose: WebSocketPort["onclose"] = null;
  onmessage: WebSocketPort["onmessage"] = null;
  onerror: WebSocketPort["onerror"] = null;
  sent: string[] = [];
  closeCalls: (number | undefined)[] = [];
  constructor(readonly url: string) {
    FakeWebSocket.instances.push(this);
  }
  send(data: string) {
    this.sent.push(data);
  }
  close(code?: number) {
    this.closeCalls.push(code);
    this.readyState = 3;
  }
  simulateOpen() {
    this.readyState = 1;
    this.onopen?.(new Event("open"));
  }
  simulateClose(code: number, reason = "") {
    this.readyState = 3;
    this.onclose?.({ code, reason } as CloseEvent);
  }
  simulateMessage(data: unknown) {
    this.onmessage?.({ data } as MessageEvent);
  }
}
