import express from "express"
import {Express, Request, Response, Router} from "express"
import axios from "axios/index"

const app: Express = express()
const router: Router = express.Router()

app.use("/api", router)
router.get("/", async (req: Request, res: Response) => {
    res.send("<h1>Hello!</h1>")
})

router.get("/list", async (req: Request, res: Response) => {
    const result = await axios.post("http://localhost:8888/api/list")
    res.json({data: result.data})
})

app.listen(8888, () => {
    console.log("Express server running on http://localhost:8888/api")
})
