import type Device from './Device';

export default class User {
	id: string;
	email: string;
	firstName: string;
	lastName: string;
	roles: string[];
	mfa: boolean;
	devices: Device[];
	dataStorage: Record<string, any> | null;
	disabled: boolean;
	createdAt: number;

	constructor(
		id: string,
		email: string,
		firstName: string,
		lastName: string,
		roles: string[],
		mfa: boolean,
		devices: Device[],
		dataStorage: Record<string, Record<string, any>> | null,
		disabled: boolean,
		createdAt: number
	) {
		this.id = id;
		this.email = email;
		this.firstName = firstName;
		this.lastName = lastName;
		this.roles = roles;
		this.mfa = mfa;
		this.devices = devices;
		this.dataStorage = dataStorage;
		this.disabled = disabled;
		this.createdAt = createdAt;
	}

	static getCreatedAt(user: User): Date {
		return new Date(user.createdAt);
	}

	static isAdmin(user: User): boolean {
		return user.id == this.DEFAULT_USERid || user.roles.includes(this.ADMIN_ROLEid);
	}

	static isSystemAdmin(user: User): boolean {
		return user.id == this.DEFAULT_USERid;
	}

	static DEFAULT_USERid = '00000000-0000-0000-0000-000000000000';
	static DEFAULT_ROLEid = '00000000-0000-0000-0000-000000000001';
	static ADMIN_ROLEid = '00000000-0000-0000-0000-000000000000';
}
