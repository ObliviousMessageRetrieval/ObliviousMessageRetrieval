// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "seal/seal.h"
#include "seal/util/polyarithsmallmod.h"
#include "regevEncryption.h"
#include <algorithm>
#include <chrono>
#include <cstddef>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <numeric>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

using namespace std;
using namespace seal;
using namespace seal::util;

void writeUtemp(const vector<uint64_t> U_temp, const int i) {
    ofstream datafile;
    datafile.open ("../data/U_temp/" + to_string(i) + ".txt");

    for(size_t i = 0; i < U_temp.size(); i++){
        datafile << U_temp[i] << "\n";
    }
    datafile.close();
}


vector<uint64_t> readUtemp(const int i, const int degree) {
    ifstream datafile;
    datafile.open ("../data/U_temp/" + to_string(i) + ".txt");

    vector<uint64_t> U_temp(degree);

    for(size_t i = 0; i < U_temp.size(); i++){
        datafile >> U_temp[i];
    }
    datafile.close();

    return U_temp;
}


/*
Helper function: Prints the name of the example in a fancy banner.
*/
inline void print_example_banner(std::string title)
{
    if (!title.empty())
    {
        std::size_t title_length = title.length();
        std::size_t banner_length = title_length + 2 * 10;
        std::string banner_top = "+" + std::string(banner_length - 2, '-') + "+";
        std::string banner_middle = "|" + std::string(9, ' ') + title + std::string(9, ' ') + "|";

        std::cout << std::endl << banner_top << std::endl << banner_middle << std::endl << banner_top << std::endl;
    }
}

/*
Helper function: Prints the parameters in a SEALContext.
*/
inline void print_parameters(const seal::SEALContext &context)
{
    auto &context_data = *context.key_context_data();

    /*
    Which scheme are we using?
    */
    std::string scheme_name;
    switch (context_data.parms().scheme())
    {
    case seal::scheme_type::bfv:
        scheme_name = "BFV";
        break;
    case seal::scheme_type::bgv:
        scheme_name = "BGV";
        break;
    case seal::scheme_type::ckks:
        scheme_name = "CKKS";
        break;
    default:
        throw std::invalid_argument("unsupported scheme");
    }
    std::cout << "/" << std::endl;
    std::cout << "| Encryption parameters :" << std::endl;
    std::cout << "|   scheme: " << scheme_name << std::endl;
    std::cout << "|   poly_modulus_degree: " << context_data.parms().poly_modulus_degree() << std::endl;

    /*
    Print the size of the true (product) coefficient modulus.
    */
    std::cout << "|   coeff_modulus size: ";
    std::cout << context_data.total_coeff_modulus_bit_count() << " (";
    auto coeff_modulus = context_data.parms().coeff_modulus();
    std::size_t coeff_modulus_size = coeff_modulus.size();
    for (std::size_t i = 0; i < coeff_modulus_size - 1; i++)
    {
        std::cout << coeff_modulus[i].bit_count() << " + ";
    }
    std::cout << coeff_modulus.back().bit_count();
    std::cout << ") bits" << std::endl;

    /*
    For the BFV scheme print the plain_modulus parameter.
    */
    if (context_data.parms().scheme() == seal::scheme_type::bfv)
    {
        std::cout << "|   plain_modulus: " << context_data.parms().plain_modulus().value() << std::endl;
    }

    std::cout << "\\" << std::endl;
}

/*
Helper function: Prints the `parms_id' to std::ostream.
*/
inline std::ostream &operator<<(std::ostream &stream, seal::parms_id_type parms_id)
{
    /*
    Save the formatting information for std::cout.
    */
    std::ios old_fmt(nullptr);
    old_fmt.copyfmt(std::cout);

    stream << std::hex << std::setfill('0') << std::setw(16) << parms_id[0] << " " << std::setw(16) << parms_id[1]
           << " " << std::setw(16) << parms_id[2] << " " << std::setw(16) << parms_id[3] << " ";

    /*
    Restore the old std::cout formatting.
    */
    std::cout.copyfmt(old_fmt);

    return stream;
}

/*
Helper function: Prints a vector of floating-point values.
*/
template <typename T>
inline void print_vector(std::vector<T> vec, std::size_t print_size = 4, int prec = 3)
{
    /*
    Save the formatting information for std::cout.
    */
    std::ios old_fmt(nullptr);
    old_fmt.copyfmt(std::cout);

    std::size_t slot_count = vec.size();

    std::cout << std::fixed << std::setprecision(prec);
    std::cout << std::endl;
    if (slot_count <= 2 * print_size)
    {
        std::cout << "    [";
        for (std::size_t i = 0; i < slot_count; i++)
        {
            std::cout << " " << vec[i] << ((i != slot_count - 1) ? "," : " ]\n");
        }
    }
    else
    {
        vec.resize(std::max(vec.size(), 2 * print_size));
        std::cout << "    [";
        for (std::size_t i = 0; i < print_size; i++)
        {
            std::cout << " " << vec[i] << ",";
        }
        if (vec.size() > 2 * print_size)
        {
            std::cout << " ...,";
        }
        for (std::size_t i = slot_count - print_size; i < slot_count; i++)
        {
            std::cout << " " << vec[i] << ((i != slot_count - 1) ? "," : " ]\n");
        }
    }
    std::cout << std::endl;

    /*
    Restore the old std::cout formatting.
    */
    std::cout.copyfmt(old_fmt);
}

/*
Helper function: Prints a matrix of values.
*/
template <typename T>
inline void print_matrix(std::vector<T> matrix, std::size_t row_size)
{
    /*
    We're not going to print every column of the matrix (there are 2048). Instead
    print this many slots from beginning and end of the matrix.
    */
    std::size_t print_size = 8;

    std::cout << std::endl;
    std::cout << "    [";
    for (std::size_t i = 0; i < print_size; i++)
    {
        std::cout << std::setw(3) << std::right << matrix[i] << ",";
    }
    std::cout << std::setw(3) << " ...,";
    for (std::size_t i = row_size - print_size; i < row_size; i++)
    {
        std::cout << std::setw(3) << matrix[i] << ((i != row_size - 1) ? "," : " ]\n");
    }
    std::cout << "    [";
    for (std::size_t i = row_size; i < row_size + print_size; i++)
    {
        std::cout << std::setw(3) << matrix[i] << ",";
    }
    std::cout << std::setw(3) << " ...,";
    for (std::size_t i = 2 * row_size - print_size; i < 2 * row_size; i++)
    {
        std::cout << std::setw(3) << matrix[i] << ((i != 2 * row_size - 1) ? "," : " ]\n");
    }
    std::cout << std::endl;
}

/*
Helper function: Print line number.
*/
inline void print_line(int line_number)
{
    std::cout << "Line " << std::setw(3) << line_number << " --> ";
}

inline
long power_seal(long x, long y, long m)
{
    if (y == 0)
        return 1;
    long p = power_seal(x, y / 2, m) % m;
    p = (p * p) % m;
 
    return (y % 2 == 0) ? p : (x * p) % m;
}

inline
long modInverse_seal(long a, long m)
{
    return power_seal(a, m - 2, m);
}


inline void multiply_power_of_X(EncryptionParameters& enc_param, const Ciphertext &encrypted, Ciphertext &destination, uint32_t index) {

    auto coeff_mod_count = enc_param.coeff_modulus().size() - 1;
    auto coeff_count = enc_param.poly_modulus_degree();
    auto encrypted_count = encrypted.size();

    destination = encrypted;

    for (int i = 0; i < (int) encrypted_count; i++) {
        for (int j = 0; j < (int) coeff_mod_count; j++) {
            negacyclic_shift_poly_coeffmod(encrypted.data(i) + (j * coeff_count),
                                           coeff_count, index,
                                           enc_param.coeff_modulus()[j],
                                           destination.data(i) + (j * coeff_count));
        }
    }
}


// for a tree with m leaf node, m >> stepSize, we first expand it to a subtree with m / stepSize leaf node
// (i.e., this subtree is the top of the whole tree)
// and then for each leaf node in this subtree, expand it into a small subtree with stepSize leaf node
// this function is the assistant function that return the top-part subtree
inline vector<Ciphertext> subExpand(const SecretKey& sk, const SEALContext& context, EncryptionParameters& enc_param, const Ciphertext &encrypted, uint32_t m,
                                    const GaloisKeys& galkey, int first_expansion_size, int t = 65537) {

    Evaluator evaluator(context);
    Plaintext two("2");
    Decryptor decryptor(context, sk);

    int logFirst = ceil(log2(first_expansion_size));

    vector<int> galois_elts;

    for (int i = 0; i < ceil(log2(m)); i++) {
        galois_elts.push_back((m + exponentiate_uint(2, i)) / exponentiate_uint(2, i));
    }

    vector<Ciphertext> temp;
    temp.push_back(encrypted);
    Ciphertext tempctxt;
    Ciphertext tempctxt_rotated;
    Ciphertext tempctxt_shifted;
    Ciphertext tempctxt_rotatedshifted;

    for (int i = 0; i < logFirst; i++) {
        vector<Ciphertext> newtemp(temp.size() << 1);
        int index_raw = (m << 1) - (1 << i);
        int index = (index_raw * galois_elts[i]) % (m << 1);

        for (uint32_t a = 0; a < temp.size(); a++) {

            evaluator.apply_galois(temp[a], galois_elts[i], galkey, tempctxt_rotated);
            evaluator.add(temp[a], tempctxt_rotated, newtemp[a]);
            multiply_power_of_X(enc_param, temp[a], tempctxt_shifted, index_raw);
            multiply_power_of_X(enc_param, tempctxt_rotated, tempctxt_rotatedshifted, index);
            evaluator.add(tempctxt_shifted, tempctxt_rotatedshifted, newtemp[a + temp.size()]);
        }

        temp = newtemp;
    }

    vector<Ciphertext>::const_iterator first = temp.begin();
    vector<Ciphertext>::const_iterator last = temp.begin() + first_expansion_size;
    vector<Ciphertext> newVec(first, last);

    return newVec;
}




// for a tree with m leaf node, m >> stepSize, we first expand it to a subtree with m / stepSize leaf node
// (i.e., this subtree is the top of the whole tree)
// and then for each leaf node in this subtree, expand it into a small subtree with stepSize leaf node
inline vector<Ciphertext> expand(const SEALContext& context, EncryptionParameters& enc_param, const Ciphertext &encrypted, uint32_t m,
                                 const GaloisKeys& galkey, int stepSize, int t = 65537) {

    Evaluator evaluator(context);
    Plaintext two("2");

    int first_expansion_size = m / stepSize;
    int logFirst = ceil(log2(first_expansion_size));
    int logm = ceil(log2(m));

    vector<int> galois_elts;

    for (int i = 0; i < ceil(log2(m)); i++) {
        galois_elts.push_back((m + exponentiate_uint(2, i)) / exponentiate_uint(2, i));
    }

    vector<Ciphertext> temp;
    temp.push_back(encrypted);
    Ciphertext tempctxt;
    Ciphertext tempctxt_rotated;
    Ciphertext tempctxt_shifted;
    Ciphertext tempctxt_rotatedshifted;

    for (int i = logFirst; i < logm - 1; i++) {
        vector<Ciphertext> newtemp(temp.size() << 1);
        int index_raw = (m << 1) - (1 << i);
        int index = (index_raw * galois_elts[i]) % (m << 1);

        for (int a = 0; a < (int) temp.size(); a++) {

            evaluator.apply_galois(temp[a], galois_elts[i], galkey, tempctxt_rotated);

            evaluator.add(temp[a], tempctxt_rotated, newtemp[a]);
            multiply_power_of_X(enc_param, temp[a], tempctxt_shifted, index_raw);
            multiply_power_of_X(enc_param, tempctxt_rotated, tempctxt_rotatedshifted, index);

            evaluator.add(tempctxt_shifted, tempctxt_rotatedshifted, newtemp[a + temp.size()]);
        }

        temp = newtemp;
    }

    // Last step of the loop
    vector<Ciphertext> newtemp(temp.size() << 1);
    int index_raw = (m << 1) - (1 << (logm - 1));
    int index = (index_raw * galois_elts[logm - 1]) % (m << 1);

    for (uint32_t a = 0; a < temp.size(); a++) {
        if (a >= (m - (1 << (logm - 1)))) { // corner case.
            evaluator.multiply_plain(temp[a], two, newtemp[a]); // plain multiplication by 2.
        } else {
            evaluator.apply_galois(temp[a], galois_elts[logm - 1], galkey, tempctxt_rotated);
            evaluator.add(temp[a], tempctxt_rotated, newtemp[a]);
            multiply_power_of_X(enc_param, temp[a], tempctxt_shifted, index_raw);
            multiply_power_of_X(enc_param, tempctxt_rotated, tempctxt_rotatedshifted, index);
            evaluator.add(tempctxt_shifted, tempctxt_rotatedshifted, newtemp[a + temp.size()]);
        }
    }

    vector<Ciphertext>::const_iterator first = newtemp.begin();
    vector<Ciphertext>::const_iterator last = newtemp.begin() + stepSize;
    vector<Ciphertext> newVec(first, last);

    return newVec;
}

vector<vector<int>> generateMatrixU_transpose(int n, const int q = 65537, const int primitive_root = 3) {
    // cout << "Generating... " << n << endl;
    vector<vector<int>> U(n,  vector<int>(n));
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < n; j++) {
            if (i == 0) {
                U[i][j] = (int) power_seal(primitive_root, j, q);
            } else if (i == n/2) {
                U[i][j] = (int) modInverse_seal(U[0][j], q);
            } else {
                U[i][j] = (int) power_seal(U[i-1][j], 3, q);
            }
        }
    }
    // cout << "Generation finished. " << endl;
    return U;
}


Ciphertext slotToCoeff(const SEALContext& context, const SEALContext& context_coeff, vector<Ciphertext>& ct_sqrt_list,
                       vector<Plaintext>& U_plain_list, const GaloisKeys& gal_keys, const int sq_rt, const int degree) {
    Evaluator evaluator(context), eval_coeff(context_coeff);
    BatchEncoder batch_encoder(context);

    chrono::high_resolution_clock::time_point time_start, time_end;
    int total_mul = 0;

    vector<Ciphertext> result(sq_rt);
    for (int iter = 0; iter < sq_rt; iter++) {
        for (int j = 0; j < (int) ct_sqrt_list.size(); j++) {
            time_start = chrono::high_resolution_clock::now();
            if (j == 0) {
                evaluator.multiply_plain(ct_sqrt_list[j], U_plain_list[iter * ct_sqrt_list.size() + j], result[iter]);
            } else {
                Ciphertext temp;
                evaluator.multiply_plain(ct_sqrt_list[j], U_plain_list[iter * ct_sqrt_list.size() + j], temp);
                evaluator.add_inplace(result[iter], temp);
            }
            time_end = chrono::high_resolution_clock::now();
            total_mul += chrono::duration_cast<chrono::microseconds>(time_end - time_start).count();
        }
    }

    for (int i = 0; i < (int) result.size(); i++) {
        evaluator.transform_from_ntt_inplace(result[i]);
    }

    for (int iter = sq_rt-1; iter > 0; iter--) {
        eval_coeff.rotate_rows_inplace(result[iter], 1, gal_keys);
        evaluator.add_inplace(result[iter-1], result[iter]);
    }

    return result[0];
}


Ciphertext slotToCoeff_WOPrepreocess_time(const SEALContext& context, const SEALContext& context_coeff, vector<Ciphertext>& ct_sqrt_list, const GaloisKeys& gal_keys,
					  uint64_t& u_time, const int sq_rt = 128, const int degree=32768, const uint64_t q = 65537, const uint64_t scalar = 1) {
  Evaluator evaluator(context), evaluator_rotate(context_coeff);
  BatchEncoder batch_encoder(context_coeff);

  chrono::high_resolution_clock::time_point time_start, time_end;
  uint64_t total_U = 0;

  time_start = chrono::high_resolution_clock::now();
  vector<vector<int>> U = generateMatrixU_transpose(degree, q);
  time_end = chrono::high_resolution_clock::now();
  total_U += chrono::duration_cast<chrono::microseconds>(time_end - time_start).count();
  // cout << "after U.\n";

  vector<Ciphertext> result(sq_rt);
  for (int iter = 0; iter < sq_rt; iter++) {
    for (int j = 0; j < (int) ct_sqrt_list.size(); j++) {

      time_start = chrono::high_resolution_clock::now();
      vector<uint64_t> U_tmp(degree);
      for (int i = 0; i < degree; i++) {
        int row_index = (i-iter) % (degree/2) < 0 ? (i-iter) % (degree/2) + degree/2 : (i-iter) % (degree/2);
        row_index = i < degree/2 ? row_index : row_index + degree/2;
        int col_index = (i + j*sq_rt) % (degree/2);
        if (j < (int) ct_sqrt_list.size() / 2) { // first half
            col_index = i < degree/2 ? col_index : col_index + degree/2;
        } else {
            col_index = i < degree/2 ? col_index + degree/2 : col_index;
        }
        U_tmp[i] = ((uint64_t) (U[row_index][col_index] * scalar)) % q;
      }
      writeUtemp(U_tmp, j*sq_rt + iter);

      Plaintext U_plain;
      batch_encoder.encode(U_tmp, U_plain);
      evaluator.transform_to_ntt_inplace(U_plain, ct_sqrt_list[j].parms_id());

      time_end = chrono::high_resolution_clock::now();
      total_U += chrono::duration_cast<chrono::microseconds>(time_end - time_start).count();

      if (j == 0) {
	    evaluator.multiply_plain(ct_sqrt_list[j], U_plain, result[iter]);
      } else {
        Ciphertext temp;
        evaluator.multiply_plain(ct_sqrt_list[j], U_plain, temp);
        evaluator.add_inplace(result[iter], temp);
      }
    }
  }

  for (int i = 0; i < (int) result.size(); i++) {
    evaluator.transform_from_ntt_inplace(result[i]);
  }
  for (int iter = sq_rt-1; iter > 0; iter--) {
    evaluator_rotate.rotate_rows_inplace(result[iter], 1, gal_keys);
    evaluator.add_inplace(result[iter-1], result[iter]);
  }

  u_time += total_U;
  
  return result[0];
}



Ciphertext slotToCoeff_WOPrepreocess(const SEALContext& context, const SEALContext& context_coeff, vector<Ciphertext>& ct_sqrt_list, const GaloisKeys& gal_keys,
                                     const int sq_rt = 128, const int degree=32768, const uint64_t q = 65537, const uint64_t scalar = 1, uint64_t process_u_time = 0) {
    Evaluator evaluator(context), evaluator_rotate(context_coeff);
    BatchEncoder batch_encoder(context_coeff);

    chrono::high_resolution_clock::time_point time_start, time_end;
    uint64_t total_U = 0;

    time_start = chrono::high_resolution_clock::now();
    vector<vector<int>> U = generateMatrixU_transpose(degree, q);
    time_end = chrono::high_resolution_clock::now();
    total_U += chrono::duration_cast<chrono::microseconds>(time_end - time_start).count();
    // cout << "after U.\n";

    vector<Ciphertext> result(sq_rt);
    for (int iter = 0; iter < sq_rt; iter++) {
        for (int j = 0; j < (int) ct_sqrt_list.size(); j++) {

            time_start = chrono::high_resolution_clock::now();
            vector<uint64_t> U_tmp(degree);
            for (int i = 0; i < degree; i++) {
                int row_index = (i-iter) % (degree/2) < 0 ? (i-iter) % (degree/2) + degree/2 : (i-iter) % (degree/2);
                row_index = i < degree/2 ? row_index : row_index + degree/2;
                int col_index = (i + j*sq_rt) % (degree/2);
                if (j < (int) ct_sqrt_list.size() / 2) { // first half
                    col_index = i < degree/2 ? col_index : col_index + degree/2;
                } else {
                    col_index = i < degree/2 ? col_index + degree/2 : col_index;
                }
                U_tmp[i] = ((uint64_t) (U[row_index][col_index] * scalar)) % q;
            }
            writeUtemp(U_tmp, j*sq_rt + iter);

            Plaintext U_plain;
            batch_encoder.encode(U_tmp, U_plain);
            evaluator.transform_to_ntt_inplace(U_plain, ct_sqrt_list[j].parms_id());

            time_end = chrono::high_resolution_clock::now();
            total_U += chrono::duration_cast<chrono::microseconds>(time_end - time_start).count();

            if (j == 0) {
                evaluator.multiply_plain(ct_sqrt_list[j], U_plain, result[iter]);
            } else {
                Ciphertext temp;
                evaluator.multiply_plain(ct_sqrt_list[j], U_plain, temp);
                evaluator.add_inplace(result[iter], temp);
            }
        }
    }

    for (int i = 0; i < (int) result.size(); i++) {
        evaluator.transform_from_ntt_inplace(result[i]);
    }

    for (int iter = sq_rt-1; iter > 0; iter--) {
        evaluator_rotate.rotate_rows_inplace(result[iter], 1, gal_keys);
        evaluator.add_inplace(result[iter-1], result[iter]);
    }

    process_u_time += total_U;
    // cout << "   TOTAL process U time: " << total_U << endl;

    return result[0];
}

uint64_t manual_mod_down_rounding(uint64_t init, uint32_t rounding_bit, const uint64_t small_p, const uint64_t large_p) {
    long double temp_f = ((long double) init) * ((long double) small_p) / ((long double) large_p);
    uint32_t decimal = (temp_f - ((int) temp_f)) * 100;
    float rounding = rounding_bit < decimal ? 1 : 0;

    long temp = ((int) (temp_f + rounding)) % small_p;
    return temp < 0 ? small_p + temp : temp;
}

