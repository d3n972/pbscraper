const axios = require("axios")
const yara = require("yara")
const rateLimit = require("axios-rate-limit")
const { writeFileSync, existsSync, mkdirSync } = require("fs")

const SCRAPER_ENDPOINT = "https://scrape.pastebin.com/api_scraping.php"
const TIMEOUT = 30 * 1000 // wait 30 secs between runs
const MAX_REQUEST = 1
const RATELIMIT_TIME = 2500
const http = rateLimit(axios.create(), { maxRequests: MAX_REQUEST, perMilliseconds: RATELIMIT_TIME })

const WATCHED_TOKENS = [
    { id: 'powershell', filter: 'powershell' },
    { id: 'base64_pe', filter: 'TVqQA' },
    { id: 'posh_script', filter: 'Invoke-' },
    { id: 'base64_pe2', filter: 'TVpQ' },
    { id: 'elf64', filter: 'f0VMR' },
    { id: 'posh_webclient', filter: 'Net.WebClient' },
    { id: 'base64_gz', filter: 'H4sI' },
    { id: 'python_syscall', filter: 'os.system' },
    { id: 'bash', filter: '#!/bin/bash' },
    { id: 'vba', filter: 'Auto_Open()' },
    { id: 'vbs', filter: 'wscript.shell' },
    { id: 'pastebin-raw-url', filter: 'pastebin.com/raw/' }

]
let ALREADY_MARKED = []
yara.initialize(function (error) {
    if (error) {
        console.error(error.message)
    } else {
        console.log("Yara init succ.")
        let scanner = yara.createScanner()
        console.log("Scanner Initialized")
        scanner.configure({
            rules: ['yara_rules/index.yar']
        }, (error, warnings) => {
            console.log("Scan starting")
            setInterval(() => {
                http.get(SCRAPER_ENDPOINT)
                    .then((response) => {
                        console.log("Rq. succ.")
                        if (typeof response.data === "string")
                            throw new Error("We fucked up, you need to wait, if I'm not mistaken.\n PBin error: " + response.data)
                        //if (response.code)
                        response.data.forEach(entry => {
                            //setTimeout(() => {
                            //  console.log("Enumerating pastes")
                            http.get(entry.scrape_url)
                                .then(r => {
                                    //            console.log("Scanning file")
                                    if (typeof r.data === "object") {
                                        let rd = r.data
                                        r.data = JSON.stringify(rd);
                                    }
                                    if (!ALREADY_MARKED.includes(entry.key)) {
                                        scanner.scan({ buffer: Buffer.from(r.data) }, (error, result) => {
                                            if (error) {
                                                console.error(error);
                                            } else {
                                                if (result.rules.length) {
                                                    console.log("match: " + JSON.stringify(result))
                                                    if (!existsSync(`./pastes/${(new Date()).toISOString().split('T')[0]}/`))
                                                        mkdirSync(`./pastes/${(new Date()).toISOString().split('T')[0]}/`);
                                                    writeFileSync(`./pastes/${(new Date()).toISOString().split('T')[0]}/${entry.key}-${result.rules[0].id}.${key}`, r.data)
                                                    ALREADY_MARKED.push(entry.key)
                                                } else {
                                                    WATCHED_TOKENS.forEach(filter => {
                                                        if (r.data.includes(filter.filter)) {
                                                            if (!existsSync(`./pastes/${(new Date()).toISOString().split('T')[0]}/`))
                                                                mkdirSync(`./pastes/${(new Date()).toISOString().split('T')[0]}/`);
                                                            writeFileSync(`./pastes/${(new Date()).toISOString().split('T')[0]}/${entry.key}.${filter.id}`, r.data)
                                                            ALREADY_MARKED.push(entry.key)
                                                            console.log(`[+] Paste id: ${entry.key} has matched with the ${filter.id} filter!`)

                                                        }
                                                    })
                                                }
                                            }
                                        });
                                    }

                                })
                                .catch(err => {
                                    console.warn(err)
                                })
                            // }, TIMEOUT)
                        });

                    })
                    .catch((err) => {
                        console.warn(err)
                    })

            }, TIMEOUT)
        })
    }
})