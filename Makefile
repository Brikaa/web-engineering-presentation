dev:
	docker-compose up --build -d
	make logs

sql:
	docker-compose exec -it db psql -U user -d app

migrate:
	docker-compose exec -it db psql -U user -d app -a -f /initial.sql

logs:
	docker-compose logs -f

stop:
	docker-compose down
