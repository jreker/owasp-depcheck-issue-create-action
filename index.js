const core = require('@actions/core');
const github = require('@actions/github');



async function run() {
    try {
        core.info("HELLO WORLD!")
    } catch (error) {
        core.setFailed(error.message);
    }
}

module.exports = {
    run
}
