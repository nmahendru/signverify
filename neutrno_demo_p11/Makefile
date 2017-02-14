SHLIBS = redist/libcastle.so.1.0.0
all: keypairgen sign destroy extractpub keyGenerate.cpp main.cpp destroy.cpp extractPub.cpp
	echo ""
keypairgen: keyGenerate.cpp PKCSDemo.cpp
	g++ -g -o keypairgen keyGenerate.cpp PKCSDemo.cpp $(SHLIBS)
sign:	main.cpp PKCSDemo.cpp
	g++ -g -o sign main.cpp PKCSDemo.cpp $(SHLIBS)
destroy:	destroy.cpp PKCSDemo.cpp
	g++ -g -o destroy destroy.cpp PKCSDemo.cpp $(SHLIBS)
extractpub: extractPub.cpp PKCSDemo.cpp PKCSDemo.h
	g++ -g -o extractpub extractPub.cpp PKCSDemo.cpp $(SHLIBS)
clean:
	rm -f sign keypairgen destroy extractpub *.o
