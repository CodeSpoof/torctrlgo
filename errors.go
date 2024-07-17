package torctrlgo

func wrapError(msg string, err error) error {
	return &wrapErr{
		msg: msg,
		err: err,
	}
}

func wrappErrors(msg string, errs []error) error {
	return &wrapErrs{
		msg:  msg,
		errs: errs,
	}
}

type wrapErr struct {
	msg string
	err error
}

func (e *wrapErr) Error() string {
	return e.msg
}

func (e *wrapErr) Unwrap() error {
	return e.err
}

type wrapErrs struct {
	msg  string
	errs []error
}

func (e *wrapErrs) Error() string {
	return e.msg
}

func (e *wrapErrs) Unwrap() []error {
	return e.errs
}
