const fs = require("fs");

// Reads the .env file when there is one (on Render the settings are already set)
if (fs.existsSync(__dirname + "/.env")) {

    for (let line of fs.readFileSync(__dirname + "/.env", "utf8").split("\n")) {

        let at = line.indexOf("=");

        if (at > 0 && !line.trim().startsWith("#")) {

            process.env[line.slice(0, at).trim()] = line.slice(at + 1).trim();

        }

    }

}


// Talks to the Supabase database. It returns the matching rows.
async function dbCall(method, table, query, body) {

    let key = process.env.SUPABASE_SERVICE_ROLE_KEY;

    let response = await fetch(process.env.SUPABASE_URL + "/rest/v1/" + table + query, {
        method: method,
        headers: {
            apikey: key,
            Authorization: "Bearer " + key,
            "Content-Type": "application/json",
            Prefer: "return=representation"
        },
        body: body ? JSON.stringify(body) : undefined
    });

    let data = await response.json().catch(function() {

        return null;

    });

    if (!response.ok) {

        throw new Error((data && data.message) || "Database error");

    }

    return data;

}


// Builds a filter like  email=eq.someone@example.com
function eq(column, value) {

    return column + "=eq." + encodeURIComponent(value);

}


module.exports = { dbCall, eq };
