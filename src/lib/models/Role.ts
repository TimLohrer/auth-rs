export default class Role {
	id: string;
	name: string;
	system: boolean;
	createdAt: number;

	constructor(id: string, name: string, system: boolean, createdAt: number) {
		this.id = id;
		this.name = name;
		this.system = system;
		this.createdAt = createdAt;
	}

	static getCreatedAt(role: Role): Date {
		return new Date(role.createdAt);
	}
}