package main

import (
	"fmt"

	"github.com/casbin/casbin/v2"
	"github.com/gofiber/fiber/v2"
)

func main() {

	enforcer, err := casbin.NewEnforcer("./casbin-poc/model.conf", "./casbin-poc/policy.csv")

	if err != nil {
		panic(fmt.Errorf("failed to create enforcer: %s", err))
	}

	app := fiber.New()

	app.Get("/users/:userId/data/:dataId", AccessControl(enforcer), func(c *fiber.Ctx) error {
		return c.Status(fiber.StatusOK).JSON(fiber.Map{"status": "success", "message": "read access allowed"})
	})

	app.Post("/users/:userId/data/:dataId", AccessControl(enforcer), func(c *fiber.Ctx) error {
		return c.Status(fiber.StatusOK).JSON(fiber.Map{"status": "success", "message": "write access allowed"})
	})
	app.Listen(":3000")

}

func AccessControl(enforcer *casbin.Enforcer) func(c *fiber.Ctx) error {

	return func(c *fiber.Ctx) error {

		user_id, _ := c.ParamsInt("userId")
		data_id, _ := c.ParamsInt("dataId")

		accessMode := ""

		if c.Method() == fiber.MethodGet {
			accessMode = "read"
		} else if c.Method() == fiber.MethodPost {
			accessMode = "write"
		}

		fmt.Println(fmt.Sprintf("user%d", user_id), fmt.Sprintf("data.%d", data_id), accessMode)
		ok, err := enforcer.Enforce(fmt.Sprintf("user%d", user_id), accessMode, fmt.Sprintf("data.%d", data_id))
		fmt.Println(fmt.Sprintf("Enforce: %t", ok), err)

		if err != nil {
			panic(err)
		}

		if !ok {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"status": "fail", "message": "access not allowed"})
		}

		return c.Next()
	}

}
