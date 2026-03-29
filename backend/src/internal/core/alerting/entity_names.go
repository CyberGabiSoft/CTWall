package alerting

import (
	"strings"

	"backend/internal/store"

	"github.com/google/uuid"
)

type alertEntityNames struct {
	project string
	product string
	scope   string
	test    string
}

func loadAlertEntityNames(st store.Store, projectID uuid.UUID, occCtx *store.AlertOccurrenceContext) alertEntityNames {
	names := alertEntityNames{
		project: projectID.String(),
	}

	if st != nil {
		if project, err := st.GetProject(projectID); err == nil && project != nil {
			if projectName := strings.TrimSpace(project.Name); projectName != "" {
				names.project = projectName
			}
		}
	}

	if occCtx == nil {
		return names
	}

	if occCtx.ProductID != nil && *occCtx.ProductID != uuid.Nil {
		names.product = occCtx.ProductID.String()
		if st != nil {
			if product, err := st.GetProductInProject(projectID, *occCtx.ProductID); err == nil && product != nil {
				if productName := strings.TrimSpace(product.Name); productName != "" {
					names.product = productName
				}
			}
		}
	}
	if occCtx.ScopeID != nil && *occCtx.ScopeID != uuid.Nil {
		names.scope = occCtx.ScopeID.String()
		if st != nil {
			if scope, err := st.GetScopeInProject(projectID, *occCtx.ScopeID); err == nil && scope != nil {
				if scopeName := strings.TrimSpace(scope.Name); scopeName != "" {
					names.scope = scopeName
				}
			}
		}
	}
	if occCtx.TestID != nil && *occCtx.TestID != uuid.Nil {
		names.test = occCtx.TestID.String()
		if st != nil {
			if testEntity, err := st.GetTestInProject(projectID, *occCtx.TestID); err == nil && testEntity != nil {
				if testName := strings.TrimSpace(testEntity.Name); testName != "" {
					names.test = testName
				}
			}
		}
	}

	return names
}
