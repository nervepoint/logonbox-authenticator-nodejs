export interface Logger {
    info(message: string): void;
    error(message: string, exception?: Error): void;
    enableDebug(_debug: boolean): void;
    isDebug(): boolean;
}

export class AppLogger implements Logger {

    private _debug = false;

    error(message: string, exception?: Error): void {
        console.error(message, exception);
    }

    info(message: string): void {
        console.log(message);
    }

    enableDebug(_debug: boolean): void {
        this._debug = _debug;
    }

    isDebug(): boolean {
        return this._debug;
    }

}