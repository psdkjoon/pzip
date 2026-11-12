/// The base class of every error pzip throws on purpose.
class PzException implements Exception {
  const PzException(this.message);

  /// A short description of what went wrong.
  final String message;

  @override
  String toString() => message;
}

/// The archive, or its list of names, is encrypted and no password was given.
class PzPasswordRequired extends PzException {
  const PzPasswordRequired() : super('A password is needed.');
}

/// The password does not fit.
class PzWrongPassword extends PzException {
  const PzWrongPassword() : super('The password is wrong.');
}

/// A feature or method pzip does not handle, for example RAR or a 7z with a BCJ
/// filter.
class PzUnsupported extends PzException {
  const PzUnsupported(super.message);
}

/// The file is damaged or is not an archive.
class PzCorrupt extends PzException {
  const PzCorrupt(super.message);
}

/// The operation was stopped through its [CancelToken].
class PzCancelled extends PzException {
  const PzCancelled() : super('Cancelled.');
}

/// Lets a long call be stopped.
///
/// Pass one to a call that takes a `cancel` argument and call [cancel] from the
/// same isolate. The call checks [isCancelled] between chunks and throws
/// [PzCancelled].
class CancelToken {
  bool _cancelled = false;

  /// Whether [cancel] was called.
  bool get isCancelled => _cancelled;

  /// Asks the running call to stop.
  void cancel() => _cancelled = true;
}

/// Thrown from a sink to stop a decoder early. It does not reach callers of the
/// public API.
class PzStop extends PzException {
  const PzStop() : super('Stopped.');
}
