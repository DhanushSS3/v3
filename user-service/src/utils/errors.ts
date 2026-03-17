export class AppError extends Error {
  constructor(
    public readonly code: string,
    public readonly statusCode: number,
    message?: string,
  ) {
    super(message ?? code);
    this.name = 'AppError';
  }
}
