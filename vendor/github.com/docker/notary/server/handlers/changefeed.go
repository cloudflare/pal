package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	ctxu "github.com/docker/distribution/context"
	"github.com/gorilla/mux"
	"golang.org/x/net/context"

	"github.com/docker/notary"
	"github.com/docker/notary/server/errors"
	"github.com/docker/notary/server/storage"
)

type changefeedResponse struct {
	NumberOfRecords int              `json:"count"`
	Records         []storage.Change `json:"records"`
}

// Changefeed returns a list of changes according to the provided filters
func Changefeed(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	var (
		vars                = mux.Vars(r)
		logger              = ctxu.GetLogger(ctx)
		qs                  = r.URL.Query()
		imageName           = vars["imageName"]
		changeID            = qs.Get("change_id")
		store, records, err = checkChangefeedInputs(logger, ctx.Value(notary.CtxKeyMetaStore), qs.Get("records"))
	)
	if err != nil {
		// err already logged and in correct format.
		return err
	}
	out, err := changefeed(logger, store, imageName, changeID, records)
	if err == nil {
		w.Write(out)
	}
	return err
}

func changefeed(logger ctxu.Logger, store storage.MetaStore, imageName, changeID string, records int64) ([]byte, error) {
	changes, err := store.GetChanges(changeID, int(records), imageName)
	if err != nil {
		logger.Errorf("500 GET could not retrieve records: %s", err.Error())
		return nil, errors.ErrUnknown.WithDetail(err)
	}
	out, err := json.Marshal(&changefeedResponse{
		NumberOfRecords: len(changes),
		Records:         changes,
	})
	if err != nil {
		logger.Error("500 GET could not json.Marshal changefeedResponse")
		return nil, errors.ErrUnknown.WithDetail(err)
	}
	return out, nil
}

func checkChangefeedInputs(logger ctxu.Logger, s interface{}, r string) (
	store storage.MetaStore, pageSize int64, err error) {

	store, ok := s.(storage.MetaStore)
	if !ok {
		logger.Error("500 GET unable to retrieve storage")
		err = errors.ErrNoStorage.WithDetail(nil)
		return
	}
	pageSize, err = strconv.ParseInt(r, 10, 32)
	if err != nil {
		logger.Errorf("400 GET invalid pageSize: %s", r)
		err = errors.ErrInvalidParams.WithDetail(
			fmt.Sprintf("invalid records parameter: %s", err.Error()),
		)
		return
	}
	if pageSize == 0 {
		pageSize = notary.DefaultPageSize
	}
	return
}
