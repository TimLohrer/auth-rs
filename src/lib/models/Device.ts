export default class Device {
	id: string;
	token: string | null;
	userAgent: string;
	os: string | null;
	ipAdress: string | null;
	createdAt: number;

	constructor(
		id: string,
		token: string | null,
		userAgent: string,
		os: string | null,
		ipAdress: string | null,
		createdAt: number
	) {
		this.id = id;
		this.token = token;
		this.userAgent = userAgent;
		this.os = os;
		this.ipAdress = ipAdress;
		this.createdAt = createdAt;
	}

	static getCreatedAt(device: Device): Date {
		return new Date(device.createdAt);
	}
}