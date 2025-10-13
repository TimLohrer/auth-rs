export default class Passkey {
	id: string;
	owner: string;
	name: string;
	createdAt: number;

	constructor(id: string, owner: string, name: string, createdAt: number) {
		this.id = id;
		this.owner = owner;
		this.name = name;
		this.createdAt = createdAt;
	}

	static getCreatedAt(passkey: Passkey): Date {
		return new Date(passkey.createdAt);
	}
}