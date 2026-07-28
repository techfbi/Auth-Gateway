export class AppError extends Error { //created inheritance from built in Error class to create custom error class. This allows us to have consistent error handling and structure across the app.
  constructor(
    public readonly message: string,
    public readonly statusCode: number = 500,
    public readonly code?: string
  ) {
    //This calls the original JavaScript Error constructor. enabling us to use all the built-in features of Error, like error.message etc and ensures stack traces are correct.
    super(message);
    this.name = "AppError"; //This sets the error name to AppError, instead of just Error. so we can know its a custom error when we catch it.
    Object.setPrototypeOf(this, AppError.prototype); //Very important for Express error middleware. It ensures that when we create an instance of AppError, it is recognized as an instance of AppError, even after transpilation to JavaScript. This is necessary for the instanceof checks in our error handling middleware to work correctly.
  }
}