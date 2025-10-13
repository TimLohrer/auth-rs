export default class Role {
	_id: string;
	name: string;
	system: boolean;
	createdAt: number;

	constructor(_id: string, name: string, system: boolean, createdAt: number) {
		this._id = _id;
		this.name = name;
		this.system = system;
		this.createdAt = createdAt;
	}

	static getCreatedAt(role: Role): Date {
		return new Date(role.createdAt);
	}
}