package com.dskim.security1.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.dskim.security1.model.User;

// CRUD 함수를 JpaRepository가 들고 있음
// @Repository annotation 없이도 IoC됨. JpaRepository를 상속했기 때문에 
public interface UserRepository extends JpaRepository<User, Integer> {

	// findBy 규칙 -> Username 문법
	// select * from user where username = 1?
	public User findByUsername(String username); // jpa query methods
}
