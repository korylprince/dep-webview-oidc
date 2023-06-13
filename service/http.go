package service

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/korylprince/dep-webview-oidc/auth"
	"github.com/korylprince/dep-webview-oidc/header"
	"github.com/korylprince/dep-webview-oidc/log"
	"golang.org/x/exp/slog"
)

const ContentTypeProfile = "application/x-apple-aspen-config"

var (
	ErrInvalidState    = errors.New("invalid state")
	ErrMismatchedState = errors.New("mismatched state")
	ErrMissingIDToken  = errors.New("missing id_token")
)

// ErrorWriter formats and writes an error response if one occurs during the enrollment process
type ErrorWriter interface {
	WriteError(status int, w http.ResponseWriter, r *http.Request, err error)
}

// TextErrorWriter is an ErrorWriter that writes text/plain responses
type TextErrorWriter struct{}

func (t TextErrorWriter) WriteError(status int, w http.ResponseWriter, r *http.Request, _ error) {
	w.Header().Set("Content-Type", "text/plain")

	resp := fmt.Sprintf("HTTP %d %s\n", status, http.StatusText(status))
	if status == http.StatusForbidden {
		resp += "You are not authorized to enroll this device."
	} else {
		resp += "Please contact your system administrator about this error."
	}
	if _, werr := w.Write([]byte(resp)); werr != nil {
		log.Attrs(r.Context(), slog.String("write-error", fmt.Sprintf("could not write error: %v", werr)))
	}
}

func (s *Service) handleError(status int, w http.ResponseWriter, r *http.Request, err error) {
	w.WriteHeader(status)
	if err != nil {
		log.Attrs(r.Context(), slog.String("error", err.Error()))
	}
	s.errWriter.WriteError(status, w, r, err)
}

// RedirectHandler parses and creates a session with the mdm request header and redirects to the OIDC authorization endpoint
func (s *Service) RedirectHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		info := new(header.MachineInfo)
		var err error

		if !s.parserDisabled {
			info, err = s.parser.Parse(r)
			if err != nil {
				s.handleError(http.StatusBadRequest, w, r, err)
				return
			}
		}

		state := uuid.New().String()

		log.Attrs(r.Context(),
			slog.String("serial", info.Serial),
			slog.String("udid", info.UDID),
			slog.String("state", state),
		)

		if err = s.store.SetState(state, info); err != nil {
			s.handleError(http.StatusInternalServerError, w, r, fmt.Errorf("could not store state: %w", err))
			return
		}

		redirectURL := s.oauth2Config.AuthCodeURL(state, s.authOpts...)
		log.LevelAttrs(r.Context(), slog.LevelDebug,
			slog.String("redirect", redirectURL),
		)

		http.Redirect(w, r, redirectURL, http.StatusFound)
	})
}

// CallbackHandler parses and verifies the response from the provider and returns an enrollment profile
func (s *Service) CallbackHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// check for error
		if errStr := r.URL.Query().Get("error"); errStr != "" {
			if errURI := r.URL.Query().Get("error"); errURI != "" {
				errStr = fmt.Sprintf("%s (%s)", errStr, errURI)
			}
			if errDesc := r.URL.Query().Get("error"); errDesc != "" {
				errStr = fmt.Sprintf("%s: %s", errStr, errDesc)
			}

			s.handleError(http.StatusInternalServerError, w, r, errors.New(errStr))
			return
		}

		// get session from state
		state := r.URL.Query().Get("state")
		log.Attrs(r.Context(), slog.String("state", state))

		info, err := s.store.GetState(state)
		if err != nil {
			s.handleError(http.StatusInternalServerError, w, r, fmt.Errorf("could not get state: %w", err))
			return
		}
		if info == nil {
			s.handleError(http.StatusBadRequest, w, r, ErrInvalidState)
			return
		}

		log.Attrs(r.Context(),
			slog.String("serial", info.Serial),
			slog.String("udid", info.UDID),
		)

		// exchange code for token
		oauth2Token, err := s.oauth2Config.Exchange(r.Context(), r.URL.Query().Get("code"))
		if err != nil {
			s.handleError(http.StatusBadRequest, w, r, fmt.Errorf("could not exchange token: %w", err))
		}

		// get id_token from token
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			s.handleError(http.StatusBadRequest, w, r, ErrInvalidState)
			return
		}

		// parse and verify id_token
		idToken, err := s.verifier.Verify(r.Context(), rawIDToken)
		if err != nil {
			s.handleError(http.StatusBadRequest, w, r, fmt.Errorf("could not verify id_token: %w", err))
			return
		}
		log.Attrs(r.Context(), slog.String("sub", idToken.Subject))

		// authorize session
		enrollCtx, err := s.authorizer.AuthorizeSession(r.Context(), info, oauth2Token, idToken)
		if err != nil {
			authErr := new(auth.AuthorizationError)
			if errors.As(err, &authErr) {
				log.Attrs(r.Context(), slog.Bool("auth", false))
				s.handleError(http.StatusForbidden, w, r, fmt.Errorf("could not authorize session: %w", err))
				return
			}
			s.handleError(http.StatusInternalServerError, w, r, fmt.Errorf("could not authorize session: %w", err))
			return
		}

		log.Attrs(r.Context(), slog.Bool("auth", true))

		// generate and send profile
		buf, err := s.enrollGenerator.GenerateEnrollProfile(r.Context(), enrollCtx)
		if err != nil {
			s.handleError(http.StatusInternalServerError, w, r, fmt.Errorf("could not generate enrollment profile: %w", err))
			return
		}

		w.Header().Set("Content-Type", ContentTypeProfile)
		w.WriteHeader(http.StatusOK)
		if _, err = w.Write(buf); err != nil {
			log.Attrs(r.Context(), slog.String("write-error", fmt.Sprintf("could not write profile: %v", err)))
		}
	})
}
