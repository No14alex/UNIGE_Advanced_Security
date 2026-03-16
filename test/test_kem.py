from oqs import oqs_engine


# Simple expression evaluation
result: dict[str, dict[str, any]] = oqs_engine(expression="2 + 2")
print(result)


# Expression with variables
result: dict[str, dict[str, any]] = oqs_engine(
    expression="a + b", variables={"a": 1, "b": 2})
print(result)
