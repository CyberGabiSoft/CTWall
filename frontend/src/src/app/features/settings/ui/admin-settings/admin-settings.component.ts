import { CommonModule } from '@angular/common';
import {
  ChangeDetectionStrategy,
  Component,
  ErrorHandler,
  WritableSignal,
  computed,
  inject,
  signal
} from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatDialog, MatDialogModule } from '@angular/material/dialog';
import { MatSnackBar } from '@angular/material/snack-bar';
import { MatTooltipModule } from '@angular/material/tooltip';
import { LucideAngularModule, CirclePlus, Filter, FolderCog, Key, Pencil, RefreshCw, Trash2 } from 'lucide-angular';
import { firstValueFrom } from 'rxjs';
import { ConfirmDialogComponent } from '../../../../shared/ui/confirm-dialog/confirm-dialog.component';
import { CopyBlockComponent } from '../../../../shared/ui/copy-block/copy-block.component';
import { DataTableComponent } from '../../../../shared/ui/data-table/data-table.component';
import { LoadingIndicatorComponent } from '../../../../shared/ui/loading-indicator/loading-indicator.component';
import { SettingsApi } from '../../data-access/settings.api';
import { AdminConnector, SettingsGeneralResponse, SettingsUser } from '../../data-access/settings.types';
import { ConnectorFormDialogComponent } from '../connector-form-dialog/connector-form-dialog.component';
import { SmtpTestDialogComponent } from '../smtp-test-dialog/smtp-test-dialog.component';
import { UserFormDialogComponent } from '../user-form-dialog/user-form-dialog.component';
import { UserPasswordResetDialogComponent } from '../user-password-reset-dialog/user-password-reset-dialog.component';
import { UserTokenOptionsDialogComponent } from '../user-token-options-dialog/user-token-options-dialog.component';
import { UserTokenDialogComponent } from '../user-token-dialog/user-token-dialog.component';
import { AdvancedFilterPanelComponent } from '../../../../shared/ui/advanced-filter-panel/advanced-filter-panel.component';
import { LoadState } from '../../../../shared/types/load-state';
import { AdminSettingsGeneralSectionController } from './admin-settings.general-section';
import { AdminSettingsConnectorsTableController } from './admin-settings.connectors-table';
import { AdminSettingsUsersTableController } from './admin-settings.users-table';

type SettingsSection = 'general' | 'connectors' | 'users';

@Component({
  selector: 'app-admin-settings',
  imports: [
    CommonModule,
    MatCardModule,
    MatButtonModule,
    MatDialogModule,
    MatTooltipModule,
    LucideAngularModule,
    DataTableComponent,
    LoadingIndicatorComponent,
    CopyBlockComponent,
    AdvancedFilterPanelComponent
  ],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './admin-settings.component.html',
  styleUrl: './admin-settings.component.scss'
})
export class AdminSettingsComponent {
  protected readonly RefreshCw = RefreshCw;
  protected readonly Filter = Filter;
  protected readonly FolderCog = FolderCog;
  protected readonly CirclePlus = CirclePlus;
  protected readonly Trash2 = Trash2;
  protected readonly Pencil = Pencil;
  protected readonly Key = Key;

  private readonly api = inject(SettingsApi);
  private readonly dialog = inject(MatDialog);
  private readonly snackBar = inject(MatSnackBar);
  private readonly errorHandler = inject(ErrorHandler);
  private readonly route = inject(ActivatedRoute);
  private readonly router = inject(Router);

  readonly activeSection = signal<SettingsSection>('general');
  readonly shellTitle = computed(() => {
    switch (this.activeSection()) {
      case 'connectors':
        return 'Connectors';
      case 'users':
        return 'Users';
      case 'general':
      default:
        return 'General';
    }
  });
  readonly shellSubtitle = computed(() => {
    switch (this.activeSection()) {
      case 'connectors':
        return 'Configure platform integrations, connector profiles, and runtime checks.';
      case 'users':
        return 'Manage platform users, roles, and service account access.';
      case 'general':
      default:
        return 'Admin panel for runtime configuration, connectors, and user management.';
    }
  });

  readonly generalStatus = signal<LoadState>('idle');
  readonly connectorsStatus = signal<LoadState>('idle');
  readonly usersStatus = signal<LoadState>('idle');

  readonly general = signal<SettingsGeneralResponse | null>(null);
  readonly connectors = signal<AdminConnector[]>([]);
  readonly users = signal<SettingsUser[]>([]);
  readonly generalSection = new AdminSettingsGeneralSectionController(() => this.general());
  readonly connectorsTable = new AdminSettingsConnectorsTableController(() => this.connectors());
  readonly usersTable = new AdminSettingsUsersTableController(() => this.users());

  readonly generalError = signal<string | null>(null);
  readonly connectorsError = signal<string | null>(null);
  readonly usersError = signal<string | null>(null);

  readonly connectorActionInProgress = signal<string | null>(null);
  readonly userActionInProgress = signal<string | null>(null);

  constructor() {
    const section = this.resolveSectionFromRoute();
    this.activeSection.set(section);
    void this.loadSection(section, true);
  }

  async refreshCurrent(): Promise<void> {
    await this.loadSection(this.activeSection(), true);
  }

  async openConnectorConfig(row: AdminConnector): Promise<void> {
    const ref = this.dialog.open(ConnectorFormDialogComponent, {
      width: '760px',
      maxWidth: '96vw',
      data: { connector: row }
    });
    const payload = await firstValueFrom(ref.afterClosed());
    if (!payload) {
      return;
    }

    this.connectorActionInProgress.set(row.type);
    try {
      await this.api.updateConnector(row.type, payload);
      await this.loadConnectors(true);
    } catch (error) {
      this.errorHandler.handleError(error);
      this.connectorsError.set('Failed to update connector.');
    } finally {
      this.connectorActionInProgress.set(null);
    }
  }

  async runConnectorTest(row: AdminConnector): Promise<void> {
    let payload: { toEmail: string } | undefined;
    if ((row.type ?? '').toLowerCase() === 'smtp') {
      const ref = this.dialog.open(SmtpTestDialogComponent, {
        width: '560px',
        maxWidth: '96vw'
      });
      const result = await firstValueFrom(ref.afterClosed());
      if (!result) {
        return;
      }
      payload = { toEmail: result.toEmail };
    }

    this.connectorActionInProgress.set(row.type);
    try {
      const result = await this.api.testConnector(row.type, payload);
      this.snackBar.open(result.message?.trim() || 'Connector test executed.', 'Close', {
        duration: 4500,
        panelClass: ['ctw-snackbar-success']
      });
      await this.loadConnectors(true);
    } catch (error) {
      this.errorHandler.handleError(error);
      this.connectorsError.set((row.type ?? '').toLowerCase() === 'smtp' ? 'Failed to send SMTP test message.' : 'Failed to execute connector test.');
    } finally {
      this.connectorActionInProgress.set(null);
    }
  }

  async createUser(): Promise<void> {
    const ref = this.dialog.open(UserFormDialogComponent, {
      width: '720px',
      maxWidth: '96vw',
      data: {
        mode: 'create',
        title: 'Create user',
        confirmLabel: 'Create'
      }
    });
    const payload = await firstValueFrom(ref.afterClosed());
    if (!payload) {
      return;
    }

    this.userActionInProgress.set('create');
    try {
      await this.api.createUser(payload);
      await this.loadUsers(true);
    } catch (error) {
      this.errorHandler.handleError(error);
      this.usersError.set('Failed to create user.');
    } finally {
      this.userActionInProgress.set(null);
    }
  }

  async editUser(row: SettingsUser): Promise<void> {
    const ref = this.dialog.open(UserFormDialogComponent, {
      width: '720px',
      maxWidth: '96vw',
      data: {
        mode: 'edit',
        title: `Edit user: ${row.email}`,
        confirmLabel: 'Save',
        user: row
      }
    });
    const payload = await firstValueFrom(ref.afterClosed());
    if (!payload) {
      return;
    }

    this.userActionInProgress.set(`edit:${row.id}`);
    try {
      await this.api.updateUser(row.id, {
        role: payload.role,
        accountType: payload.accountType,
        nickname: payload.nickname,
        fullName: payload.fullName
      });
      await this.loadUsers(true);
    } catch (error) {
      this.errorHandler.handleError(error);
      this.usersError.set('Failed to update user.');
    } finally {
      this.userActionInProgress.set(null);
    }
  }

  async resetUserPassword(row: SettingsUser): Promise<void> {
    if (this.usersTable.isServiceAccount(row)) {
      return;
    }
    const ref = this.dialog.open(UserPasswordResetDialogComponent, {
      width: '620px',
      maxWidth: '96vw',
      data: {
        email: row.email
      }
    });
    const payload = await firstValueFrom(ref.afterClosed());
    if (!payload) {
      return;
    }

    this.userActionInProgress.set(`password:${row.id}`);
    try {
      await this.api.resetUserPassword(row.id, payload);
      await this.loadUsers(true);
    } catch (error) {
      this.errorHandler.handleError(error);
      this.usersError.set('Failed to reset user password.');
    } finally {
      this.userActionInProgress.set(null);
    }
  }

  async createServiceAccountToken(row: SettingsUser): Promise<void> {
    if (row.accountType !== 'SERVICE_ACCOUNT') {
      return;
    }
    const optionsRef = this.dialog.open(UserTokenOptionsDialogComponent, {
      width: '560px',
      maxWidth: '96vw'
    });
    const options = await firstValueFrom(optionsRef.afterClosed());
    if (options === null || options === undefined) {
      return;
    }

    this.userActionInProgress.set(`token:${row.id}`);
    try {
      const result = await this.api.createUserToken(row.id, options);
      this.dialog.open(UserTokenDialogComponent, {
        width: '720px',
        maxWidth: '96vw',
        data: {
          userEmail: row.email,
          token: result.token,
          tokenId: result.tokenId,
          name: result.name,
          createdAt: result.createdAt,
          expiresAt: result.expiresAt
        }
      });
      await this.loadUsers(true);
    } catch (error) {
      this.errorHandler.handleError(error);
      this.usersError.set('Failed to generate service account token.');
    } finally {
      this.userActionInProgress.set(null);
    }
  }

  async deleteUser(row: SettingsUser): Promise<void> {
    const ref = this.dialog.open(ConfirmDialogComponent, {
      width: '520px',
      maxWidth: '96vw',
      data: {
        title: `Delete user: ${row.email}`,
        message: 'This action removes the user from the platform. Continue?',
        confirmLabel: 'Delete user',
        cancelLabel: 'Cancel'
      }
    });
    const confirmed = await firstValueFrom(ref.afterClosed());
    if (!confirmed) {
      return;
    }

    this.userActionInProgress.set(row.id);
    try {
      await this.api.deleteUser(row.id);
      await this.loadUsers(true);
    } catch (error) {
      this.errorHandler.handleError(error);
      this.usersError.set('Failed to delete user.');
    } finally {
      this.userActionInProgress.set(null);
    }
  }

  openManageProjects(): void {
    void this.router.navigate(['/admin/projects']);
  }

  openEvents(): void {
    void this.router.navigate(['/events']);
  }

  testStatusClass(value: string | null | undefined): string {
    switch (value) {
      case 'PASSED':
        return 'status status--ok';
      case 'FAILED':
        return 'status status--err';
      default:
        return 'status status--na';
    }
  }

  connectorTestButtonLabel(row: AdminConnector): string {
    if ((row.type ?? '').toLowerCase() === 'smtp') {
      return 'Send test email';
    }
    return 'Test connection';
  }

  private async loadSection(section: SettingsSection, force: boolean): Promise<void> {
    if (section === 'general') {
      await this.loadGeneral(force);
      return;
    }
    if (section === 'connectors') {
      await this.loadConnectors(force);
      return;
    }
    await this.loadUsers(force);
  }

  private async loadGeneral(force: boolean): Promise<void> {
    await this.loadWithState(force, {
      status: this.generalStatus,
      error: this.generalError,
      errorMessage: 'Failed to load general settings.',
      request: () => this.api.getGeneral(),
      apply: (payload) => this.general.set(payload)
    });
  }

  private async loadConnectors(force: boolean): Promise<void> {
    await this.loadWithState(force, {
      status: this.connectorsStatus,
      error: this.connectorsError,
      errorMessage: 'Failed to load connectors.',
      request: () => this.api.listConnectors(),
      apply: (items) => this.connectors.set(items.slice().sort((a, b) => a.type.localeCompare(b.type)))
    });
  }

  private async loadUsers(force: boolean): Promise<void> {
    await this.loadWithState(force, {
      status: this.usersStatus,
      error: this.usersError,
      errorMessage: 'Failed to load users.',
      request: () => this.api.listUsers(),
      apply: (items) => this.users.set(items.slice().sort((a, b) => a.email.localeCompare(b.email)))
    });
  }

  private async loadWithState<T>(
    force: boolean,
    args: {
      status: WritableSignal<LoadState>;
      error: WritableSignal<string | null>;
      errorMessage: string;
      request: () => Promise<T>;
      apply: (payload: T) => void;
    }
  ): Promise<void> {
    if (!force && (args.status() === 'loaded' || args.status() === 'loading')) {
      return;
    }
    args.status.set('loading');
    args.error.set(null);
    try {
      const payload = await args.request();
      args.apply(payload);
      args.status.set('loaded');
    } catch (error) {
      this.errorHandler.handleError(error);
      args.status.set('error');
      args.error.set(args.errorMessage);
    }
  }

  private resolveSectionFromRoute(): SettingsSection {
    const raw = this.route.snapshot.data['section'];
    if (raw === 'connectors' || raw === 'users') {
      return raw;
    }
    return 'general';
  }
}
