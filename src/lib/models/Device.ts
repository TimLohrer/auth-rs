export default class Device {
	id: string;
	token: string;
	userAgent: string;
	os: string | null;
	ipAdress: string | null;
	createdAt: any;

	constructor(
		id: string,
		token: string,
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

	static getExpiresAt(device: Device): Date {
		const tokenData = device.token.split('.');
		if (tokenData.length !== 3) return new Date(0);

		try {
			const payload = JSON.parse(atob(tokenData[1]));
			if (!payload.exp) return new Date(0);
			return new Date(payload.exp * 1000);
		} catch {
			return new Date(0);
		}
	}
}