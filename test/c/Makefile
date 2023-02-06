
test: main
	./main

cart.h:
	(cd ../..; cbindgen --config ./cbindgen.toml --crate cart_container --output cart.h --lang c)
	mv ../../cart.h ./cart.h

libcart.a:
	(cd ../..; cargo build --lib --release)
	mv ../../target/release/libcart.a ./libcart.a

main: main.c cart.h libcart.a
	gcc -o ./main main.c libcart.a -lpthread

clean:
	rm -f cart.h ./main ./libcart.a ./cart.h.cart ./cart_copy.h