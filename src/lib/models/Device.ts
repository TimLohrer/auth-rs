export default class Device {
	id: string;
	token: string | null;
	userAgent: string;
	os: string | null;
	ipAdress: string | null;
	createdAt: any;

	constructor(
		id: string,
		token: string | null,
		userAgent: string,
		os: string | null,
		ipAdress: string | null,
		createdAt: any
	) {
		this.id = id;
		this.token = token;
		this.userAgent = userAgent;
		this.os = os;
		this.ipAdress = ipAdress;
		this.createdAt = createdAt;
	}

	static getCreatedAt(device: Device): Date {
		// @ts-ignore
		return new Date(parseInt(device.createdAt.$date.$numberLong) ?? 0);
	}
}