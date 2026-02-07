import { accessSync, constants, readFileSync, existsSync, realpathSync } from 'fs'
import * as path from 'path'
import { Database } from 'bun:sqlite'
import { DATA } from '..'

export function isValidFilePath(p: string, checkExistence?: boolean): boolean {
    if (!p || typeof p !== 'string') return false
    if (p.startsWith('-')) return false

    try {
        const abs = path.resolve(p)
        if (checkExistence) {
            accessSync(abs, constants.F_OK)
        }
        return true
    } catch {
        return false
    }
}

export function strerr(err: any): string {
    return err instanceof Error ? `${err.message}\n${err.stack}` : String(err)
}

export function validateSQLite(dbPath: string): boolean {
    let db: Database | undefined
    try {
        let absolutePath: string
        try {
            absolutePath = realpathSync(dbPath)
        } catch {
            absolutePath = path.resolve(dbPath)
        }

        if (!existsSync(absolutePath)) {
            DATA.lastError = `File does not exist at path: ${absolutePath}`
            return false
        }

        // Open readonly — we only need to check for the ItemTable.
        db = new Database(absolutePath, { readonly: true })

        const tableCheck = db.query(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='ItemTable'"
        ).get()

        db.close()
        return !!tableCheck
    } catch (err) {
        if (db) {
            try { db.close() } catch {}
        }
        DATA.lastError = strerr(err)
        return false
    }
}

export function validateLocalState(keyPath: string): boolean {
    try {
        const absolutePath = path.resolve(keyPath)
        accessSync(absolutePath, constants.R_OK)

        const data = JSON.parse(readFileSync(absolutePath).toString('utf8'))
        const oscrypt = data.os_crypt

        if (!oscrypt) {
            DATA.lastError = 'no os_crypt key in json'
            return false
        }

        const keyb64 = oscrypt.encrypted_key
        if (!keyb64) {
            DATA.lastError = 'no encrypted_key key in os_crypt object'
            return false
        }

        // Basic base64 length check or atob validation
        if (atob(keyb64).length <= 0) {
            DATA.lastError = 'decrypted key length is zero'
            return false
        }

        return true
    } catch (err) {
        DATA.lastError = strerr(err)
        return false
    }
}