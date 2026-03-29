export interface ProjectSummary {
  id: string;
  name: string;
  description?: string;
  archivedAt?: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface SelectedProjectResponse {
  projectId: string;
  name: string;
  projectRole: SelectedProjectRole;
}

export interface ProjectMember {
  id: string;
  email: string;
  role: 'ADMIN' | 'WRITER' | 'READER';
  accountType: 'USER' | 'SERVICE_ACCOUNT';
  fullName?: string;
  projectRole: ProjectRole;
}

export interface ProjectsListItem extends ProjectSummary {
  membersCount: number;
}

export interface ProjectCreateRequest {
  name: string;
  description?: string;
}

export interface ProjectUpdateRequest {
  name: string;
  description?: string;
}

export interface ProjectDeleteRequest {
  acknowledge: boolean;
}

export type ProjectRole = 'ADMIN' | 'WRITER' | 'READER';
export type SelectedProjectRole = ProjectRole | 'NONE';

export interface ProjectMemberAssignment {
  userId: string;
  projectRole: ProjectRole;
}

export interface ProjectMembersRequest {
  members: ProjectMemberAssignment[];
}
