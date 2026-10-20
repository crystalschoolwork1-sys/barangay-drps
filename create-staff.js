// Run:  npm run create-staff -- "Full Name" email@example.com password123

const bcrypt = require("bcryptjs");
const { dbCall } = require("./db");


async function main() {

    let name = process.argv[2];
    let email = (process.argv[3] || "").trim().toLowerCase();
    let password = process.argv[4];

    if (!name || !email || !password) {

        console.log('Use:  npm run create-staff -- "Full Name" email@example.com password');

        return;

    }

    try {

        await dbCall("POST", "accounts", "", {
            role: "staff",
            name: name,
            email: email,
            password_hash: await bcrypt.hash(password, 10)
        });

        console.log("Staff account created for " + email);

    } catch (error) {

        console.log("Could not create the account:", error.message);

    }

}


main();
