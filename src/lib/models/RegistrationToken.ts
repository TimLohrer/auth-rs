export default class RegistrationToken {
	id: string;
	code: string;
	maxUses: number;
	uses: string[];
	autoRoles: string[];
	expiresIn: number | null;
	expiresFrom: number | null;
	createdAt: number;

	constructor(
		id: string,
		code: string,
		maxUses: number,
		uses: string[],
		autoRoles: string[],
		expiresIn: number | null,
		expiresFrom: number | null,
		createdAt: number
	) {
		this.id = id;
		this.code = code;
		this.maxUses = maxUses;
		this.uses = uses;
		this.autoRoles = autoRoles;
		this.expiresIn = expiresIn;
		this.expiresFrom = expiresFrom;
		this.createdAt = createdAt;
	}

	static getUrl(token: RegistrationToken): string {
		return `${document.location.origin}/register?registration_code=${token.code}`;
	}

	static getCreatedAt(token: RegistrationToken): Date {
		return new Date(token.createdAt);
	}

	static getExpiresAt(token: RegistrationToken): Date | null {
		return token.expiresIn && token.expiresFrom
			? new Date(token.expiresFrom + token.expiresIn - Date.now())
			: null;
	}
}