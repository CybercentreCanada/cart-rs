
test: main
	./main

cart.h:
	(cd ../../shared_library; cbindgen --config ./cbindgen.toml --crate cart --output cart.h --lang c)
	mv ../../shared_library/cart.h ./cart.h

libcart.a:
	(cd ../..; cargo build --lib --release)
	mv ../../target/release/libcart.a ./libcart.a

main: main.c cart.h libcart.a
	gcc -o ./main main.c libcart.a -lpthread

clean:
	rm -f cart.h ./main ./libcart.a ./cart.h.cart ./cart_copy.h