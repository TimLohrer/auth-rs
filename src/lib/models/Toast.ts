export class Toast {
    id: string = crypto.randomUUID();
    createdAt: number = Date.now();
    message: string;
    type: 'success' | 'error' | 'info';
    ttl: number = 5000; // default time to live in ms

    constructor(message: string, type: 'success' | 'error' | 'info', ttl?: number) {
        this.message = message;
        this.type = type;
        this.ttl = ttl ?? this.ttl;
    }
}