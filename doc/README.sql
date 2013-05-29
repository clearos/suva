SQL Queries and Parameter Substitution
--------------------------------------

Suva/3 database queries:

	query-hostkey
		Look-up device's host key.  This is most likeley a SELECT statement.
		You can use the following tokens which will be replaced with the value:

			%d	Device name/ID (required)
			%o	Organization (optional)

	update-pool-client:
		This is run when the state of a pool client changes.  If the query fails
		because an existing record does not exist, the storage engine will run the
		insert-pool-client query (below).  You can use the following tokens:

			%n	Node name (optional)
			%p	Pool name (optional)
			%d	Device name/ID (required)
			%o	Organization (optional)
			%s	State (optional)

	insert-pool-client:
		Run when the above update-pool-client fails because there was no record to
		update.  Valid replacement tokens are the same as update-pool-client.

	purge-pool-clients:
		Run when an organization's storage engine is started and stopped.  This
		query should purge all records belonging to the corresponding Suva/3 node.
		Valid replacement tokens are:

		%n	Node name (required)
		%o	Organization (optional)

vi: ts=2 syntax=text
