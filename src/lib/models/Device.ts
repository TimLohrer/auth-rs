export default class Device {
	id: string;
	token: string | null;
	userAgent: string;
	os: string | null;
	ipAddress: string | null;
	createdAt: number;

	constructor(
		id: string,
		token: string | null,
		userAgent: string,
		os: string | null,
		ipAddress: string | null,
		createdAt: number
	) {
		this.id = id;
		this.token = token;
		this.userAgent = userAgent;
		this.os = os;
		this.ipAddress = ipAddress;
		this.createdAt = createdAt;
	}

	static getCreatedAt(device: Device): Date {
		return new Date(device.createdAt);
	}
}