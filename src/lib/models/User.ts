import type Device from './Device';

export default class User {
	_id: string;
	email: string;
	firstName: string;
	lastName: string;
	roles: string[];
	mfa: boolean;
	devices: Device[];
	dataStorage: Record<string, any> | null;
	disabled: boolean;
	createdAt: any;

	constructor(
		_id: string,
		email: string,
		firstName: string,
		lastName: string,
		roles: string[],
		mfa: boolean,
		devices: Device[],
		dataStorage: Record<string, any> | null,
		disabled: boolean,
		createdAt: any
	) {
		this._id = _id;
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
		// @ts-ignore
		return new Date(parseInt(user.createdAt.$date.$numberLong) ?? 0);
	}

	static isAdmin(user: User): boolean {
		return user._id == this.DEFAULT_USER_ID || user.roles.includes(this.ADMIN_ROLE_ID);
	}

	static isSystemAdmin(user: User): boolean {
		return user._id == this.DEFAULT_USER_ID;
	}

	static DEFAULT_USER_ID = '00000000-0000-0000-0000-000000000000';
	static DEFAULT_ROLE_ID = '00000000-0000-0000-0000-000000000001';
	static ADMIN_ROLE_ID = '00000000-0000-0000-0000-000000000000';
}
