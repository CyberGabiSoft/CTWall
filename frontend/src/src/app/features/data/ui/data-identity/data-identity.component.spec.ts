import { ErrorHandler } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { MatDialog } from '@angular/material/dialog';
import { of } from 'rxjs';
import { AuthStore } from '../../../auth/auth.store';
import { IdentityApi } from '../../data-access/identity.api';
import { ProjectsApi } from '../../../projects/data-access/projects.api';
import { ProjectContextService } from '../../../projects/data-access/project-context.service';
import { DataIdentityComponent } from './data-identity.component';

describe('DataIdentityComponent (TestBed)', () => {
  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [DataIdentityComponent],
      providers: [
        {
          provide: IdentityApi,
          useValue: {
            listGroups: async () => [
              {
                id: 'group-1',
                projectId: 'project-1',
                name: 'Core Owners',
                description: 'Primary owners',
                createdAt: '2026-02-21T00:00:00Z',
              },
            ],
            listGroupMembers: async () => [
              {
                groupId: 'group-1',
                userId: 'user-1',
                role: 'OWNER',
                email: 'owner@example.com',
                fullName: 'Owner User',
                createdAt: '2026-02-21T00:00:00Z',
              },
            ],
            createGroup: async () => {
              throw new Error('not used in this test');
            },
            replaceGroupMembers: async () => undefined,
          },
        },
        {
          provide: ProjectsApi,
          useValue: {
            listProjectMembers: async () => [
              {
                id: 'user-1',
                email: 'owner@example.com',
                role: 'ADMIN',
                accountType: 'USER',
                fullName: 'Owner User',
                projectRole: 'ADMIN',
              },
            ],
          },
        },
        {
          provide: ProjectContextService,
          useValue: {
            initialize: async () => undefined,
            selectedProjectId: () => 'project-1',
            canAdmin: () => true,
            canWrite: () => true,
          },
        },
        {
          provide: AuthStore,
          useValue: {
            user: () => ({
              id: 'user-1',
              email: 'owner@example.com',
              role: 'ADMIN',
              accountType: 'USER',
            }),
          },
        },
        {
          provide: MatDialog,
          useValue: {
            open: () => ({
              afterClosed: () => of(null),
            }),
          },
        },
        {
          provide: ErrorHandler,
          useValue: {
            handleError: () => {},
          },
        },
      ],
    }).compileComponents();
  });

  it('renders user groups shell and loads first group', async () => {
    const fixture = TestBed.createComponent(DataIdentityComponent);
    fixture.detectChanges();
    await fixture.componentInstance.refresh();
    fixture.detectChanges();

    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.textContent).toContain('User Groups');
    expect(fixture.componentInstance.selectedGroupId()).toBe('group-1');
    expect(fixture.componentInstance.groupsStatus()).toBe('loaded');
  });

  it('toggles extended filter visibility for group/member tables', async () => {
    const fixture = TestBed.createComponent(DataIdentityComponent);
    fixture.detectChanges();
    await fixture.whenStable();

    const component = fixture.componentInstance;
    expect(component.groupFilterVisible().name).toBe(false);
    expect(component.memberFilterVisible().email).toBe(false);

    component.toggleGroupFilter('name', new Event('click'));
    component.toggleMemberFilter('email', new Event('click'));

    expect(component.groupFilterVisible().name).toBe(true);
    expect(component.memberFilterVisible().email).toBe(true);
  });
});
