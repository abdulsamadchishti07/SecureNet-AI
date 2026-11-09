"""Per-client bounded notification queues; slow readers cannot delay ingestion."""

import asyncio
from contextlib import suppress
from dataclasses import dataclass
import secrets
import time
from threading import Lock


class WebSocketTickets:
    """Short-lived, single-use browser capabilities; never put a JWT in a URL."""
    def __init__(self, clock=time.monotonic, capacity=1024):
        self.clock, self.capacity, self.tickets = clock, capacity, {}
        self.lock = Lock()

    def issue(self, user_id, token_expires):
        with self.lock:
            now = self.clock()
            self.tickets = {key: value for key, value in self.tickets.items() if value[2] > now}
            if len(self.tickets) >= self.capacity:
                raise ValueError("WebSocket ticket capacity reached")
            ticket = secrets.token_urlsafe(32)
            self.tickets[ticket] = (user_id, token_expires, now + 30)
            return ticket

    def consume(self, ticket):
        with self.lock:
            entry = self.tickets.pop(ticket, None)
        if entry is None or entry[2] <= self.clock():
            raise ValueError("Invalid or expired WebSocket ticket")
        return entry[0], entry[1]


@dataclass
class Subscription:
    websocket: object
    queue: asyncio.Queue
    task: asyncio.Task | None = None


class ConnectionManager:
    def __init__(self, capacity=100, max_clients=256, send_timeout=5):
        self.capacity, self.max_clients, self.send_timeout = capacity, max_clients, send_timeout
        self.connections = {}

    async def connect(self, websocket):
        if len(self.connections) >= self.max_clients:
            await websocket.close(code=1013)
            return None
        await websocket.accept()
        subscription = Subscription(websocket, asyncio.Queue(maxsize=self.capacity))
        self.connections[id(websocket)] = subscription
        subscription.task = asyncio.create_task(self._send(subscription))
        return subscription

    async def _send(self, subscription):
        try:
            while True:
                message = await subscription.queue.get()
                await asyncio.wait_for(subscription.websocket.send_json(message), self.send_timeout)
        except asyncio.CancelledError:
            raise
        except Exception:
            with suppress(Exception):
                await asyncio.wait_for(subscription.websocket.close(code=1013), 1)
        finally:
            self.connections.pop(id(subscription.websocket), None)

    def broadcast(self, message):
        for subscription in list(self.connections.values()):
            try:
                subscription.queue.put_nowait(message)
            except asyncio.QueueFull:
                self.connections.pop(id(subscription.websocket), None)
                asyncio.create_task(self.disconnect(subscription, code=1013))

    async def disconnect(self, subscription, code=1000):
        self.connections.pop(id(subscription.websocket), None)
        subscription.task.cancel()
        with suppress(asyncio.CancelledError, Exception):
            await subscription.task
        with suppress(Exception):
            await asyncio.wait_for(subscription.websocket.close(code=code), 1)

    async def close(self):
        await asyncio.gather(*(self.disconnect(client) for client in list(self.connections.values())))
