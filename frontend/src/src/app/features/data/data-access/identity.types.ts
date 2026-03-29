export type GroupMemberRole = 'OWNER' | 'EDITOR' | 'VIEWER';

export interface UserGroup {
  id: string;
  projectId: string;
  name: string;
  description?: string;
  createdAt: string;
  createdBy?: string;
}

export interface UserGroupMember {
  groupId: string;
  userId: string;
  role: GroupMemberRole;
  createdAt: string;
  createdBy?: string;
  email?: string;
  fullName?: string;
}

export interface GroupCreateRequest {
  name: string;
  description?: string;
}

export interface GroupMemberAssignment {
  userId: string;
  role: GroupMemberRole;
}

export interface GroupMembersSetRequest {
  members: GroupMemberAssignment[];
}
