package com.zdawn.jwt.spi.impl;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Types;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.sql.DataSource;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.zdawn.jwt.spi.Token;
import com.zdawn.jwt.spi.TokenStore;
import com.zdawn.jwt.spi.WebToken;

public class JdbcTokenStore implements TokenStore {
	private static Logger logger = LoggerFactory.getLogger(JdbcTokenStore.class);
	
	private DataSource dataSource;
	/**
	 * token表名
	 */
	private String tableName = "sys_token";
	/**
	 * 查询表是否存在,不存在则创建
	 * @throws Exception
	 */
	public void creatTokenTable() throws Exception {
		Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        try {
        	String sql = "select * from "+tableName+" where 1<0";
        	con = dataSource.getConnection();
            ps = con.prepareStatement(sql);
            rs=ps.executeQuery();
        } catch (SQLException e) {
        	closeResultSet(rs);
        	closeStatement(ps);
			//创建表
			String sql = "create table "+tableName+"(token_id varchar(64) primary key,"
					   +"user_id varchar(32),token_state decimal(1),create_time decimal(15),"
					   +"last_use_time decimal(15),token_type decimal(1),use_number decimal(3))";
			try {
	            ps = con.prepareStatement(sql);
	            ps.executeUpdate();
			} catch (SQLException e1) {
				logger.error("表创建失败",e1);
			}
        } finally {
        	closeResultSet(rs);
        	closeStatement(ps);
        	closeConnection(con);
        }
	}
	
	/**
	 * 查询历史表是否存在,不存在则创建
	 * @throws Exception
	 */
	public void creatTokenHisTable() throws Exception {
		Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        try {
        	String sql = "select * from "+tableName+"_his where 1<0";
        	con = dataSource.getConnection();
            ps = con.prepareStatement(sql);
            rs=ps.executeQuery();
        } catch (SQLException e) {
        	closeResultSet(rs);
        	closeStatement(ps);
			//创建表
			String sql = "create table "+tableName+"_his(token_id varchar(64) primary key,"
					   +"user_id varchar(32),token_state decimal(1),create_time decimal(15),"
					   +"last_use_time decimal(15),token_type decimal(1),use_number decimal(3))";
			try {
	            ps = con.prepareStatement(sql);
	            ps.executeUpdate();
			} catch (SQLException e1) {
				logger.error("历史表创建失败",e1);
			}
        } finally {
        	closeResultSet(rs);
        	closeStatement(ps);
        	closeConnection(con);
        }
	}

	@Override
	public void saveToken(Token token) throws SQLException {
		Connection con = null;
        PreparedStatement ps = null;
        String sql = "insert into "+tableName+"(token_id,user_id,token_state,create_time,last_use_time,token_type,use_number)"
                + " values(?,?,?,?,?,?,?)";
        try {
            con = dataSource.getConnection();
            ps = con.prepareStatement(sql);
            set(ps, 1, token.getTokenId(), Types.VARCHAR);
            set(ps, 2, token.getUserId(), Types.VARCHAR);
            set(ps, 3, token.getTokenState(), Types.INTEGER);
            set(ps, 4, token.getCreateTime(), Types.BIGINT);
            set(ps, 5, token.getLastUseTime(), Types.BIGINT);
            set(ps, 6, token.getTokenType(), Types.INTEGER);
            set(ps, 7, token.getUseNumber(), Types.INTEGER);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw e;
        } finally {
            closeStatement(ps);
            closeConnection(con);
        }
	}

	@Override
	public Token queryTokenById(String tokenId) throws SQLException {
		Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        Token token =null;
        try {
        	String sql = "select token_id,user_id,token_state,create_time,last_use_time,token_type,use_number from "
        			     +tableName+" where token_id=?";
        	con = dataSource.getConnection();
            ps = con.prepareStatement(sql);
            set(ps, 1, tokenId, Types.VARCHAR);
            rs = ps.executeQuery();
            while(rs.next()){
            	token = new Token();
            	token.setTokenId(rs.getString("token_id"));
            	token.setUserId(rs.getString("user_id"));
            	token.setTokenState(rs.getInt("token_state"));
            	token.setCreateTime(rs.getLong("create_time"));
            	token.setLastUseTime(rs.getLong("last_use_time"));
            	token.setTokenType(rs.getInt("token_type"));
            	token.setUseNumber(rs.getInt("use_number"));
            }
        } catch (SQLException e) {
        	logger.error("查询"+tableName+"表失败",e);
            throw e;
        } finally {
        	closeResultSet(rs);
        	closeStatement(ps);
        	closeConnection(con);
        }
        return token;
	}
	
	@Override
	public List<Token> queryTokenByUserId(String userId) throws SQLException {
		Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        List<Token> tokenList =new ArrayList<>();
        try {
        	String sql = "select token_id,user_id,token_state,create_time,last_use_time,token_type,use_number from "
        			     +tableName+" where user_id=?";
        	con = dataSource.getConnection();
            ps = con.prepareStatement(sql);
            set(ps, 1, userId, Types.VARCHAR);
            rs = ps.executeQuery();
            while(rs.next()){
            	Token token = new Token();
            	token.setTokenId(rs.getString("token_id"));
            	token.setUserId(rs.getString("user_id"));
            	token.setTokenState(rs.getInt("token_state"));
            	token.setCreateTime(rs.getLong("create_time"));
            	token.setLastUseTime(rs.getLong("last_use_time"));
            	token.setTokenType(rs.getInt("token_type"));
            	token.setUseNumber(rs.getInt("use_number"));
            	tokenList.add(token);
            }
        } catch (SQLException e) {
        	logger.error("查询"+tableName+"表失败",e);
            throw e;
        } finally {
        	closeResultSet(rs);
        	closeStatement(ps);
        	closeConnection(con);
        }
        return tokenList;
	}

	@Override
	public void updateToken(Token token) throws SQLException {
		Connection con = null;
        PreparedStatement ps = null;
        String sql = "update "+tableName+" set token_state=?,last_use_time=?,token_type =?,use_number=?"
        		    +" where token_id=?";
        try {
            con = dataSource.getConnection();
            ps = con.prepareStatement(sql);
            set(ps, 1, token.getTokenState(), Types.INTEGER);
            set(ps, 2, token.getLastUseTime(), Types.BIGINT);
            set(ps, 3, token.getTokenType(), Types.INTEGER);
            set(ps, 4, token.getUseNumber(), Types.INTEGER);
            set(ps, 5, token.getTokenId(), Types.VARCHAR);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw e;
        } finally {
            closeStatement(ps);
            closeConnection(con);
        }
	}

	@Override
	public void delTokenById(String tokenId) throws SQLException {
		Connection con = null;
		PreparedStatement ps = null;
		try {
			String sql = "delete from "+tableName+" where token_id = ?";
            con = dataSource.getConnection();
            ps = con.prepareStatement(sql);
            set(ps, 1, tokenId, Types.VARCHAR);
            ps.executeUpdate();
		} catch (SQLException e) {
			throw e;
		} finally {
			closeStatement(ps);
			closeConnection(con);
		}
	}
	
	
	@Override
	public void clearTokenByOverTime(int expireTime) throws SQLException {
		Connection con = null;
		PreparedStatement ps = null;
		try {
			long time =(new Date().getTime()-expireTime*60*1000);//超时时间
			String sql = "delete from "+tableName+" where last_use_time <= ?";
            con = dataSource.getConnection();
            ps = con.prepareStatement(sql);
            set(ps, 1, time, Types.BIGINT);
            ps.executeUpdate();
		} catch (SQLException e) {
			throw e;
		} finally {
			closeStatement(ps);
			closeConnection(con);
		}
	}
	
	@Override
	public void moveHistoryTokenByOverTime(int expireTime) throws Exception {
		Connection con = null;
        PreparedStatement ps = null;
        long time =(new Date().getTime()-expireTime*60*1000);//超时时间
        String sql ="insert into "+tableName+"_his(token_id,user_id,token_state,create_time,last_use_time,token_type,use_number)"
        		   +" select token_id,user_id,token_state,create_time,last_use_time,token_type,use_number"
        		   +" from "+tableName+" where last_use_time <= ?";
	    try {
	        con = dataSource.getConnection();
	        ps = con.prepareStatement(sql);
	        set(ps, 1, time, Types.BIGINT);
	        ps.executeUpdate();
	    } catch (SQLException e) {
	        throw e;
	    } finally {
	        closeStatement(ps);
	    }
	   //删除
  		try {
      		ps = con.prepareStatement("delete from "+tableName+" where last_use_time <= ?");
      		set(ps, 1, time, Types.BIGINT);
      		ps.executeUpdate();
      	} catch (SQLException e) {
      		throw e;
      	} finally {
      		closeStatement(ps);
      		closeConnection(con);
      	}
	}
	
	@Override
	public void moveHistoryToken(String tokenId) throws SQLException {
		Connection con = null;
        PreparedStatement ps = null;
        String sql ="insert into "+tableName+"_his(token_id,user_id,token_state,create_time,last_use_time,token_type,use_number)"
        		   +" select token_id,user_id,token_state,create_time,last_use_time,token_type,use_number"
        		   +" from "+tableName+" where token_id=?";
	    try {
	        con = dataSource.getConnection();
	        ps = con.prepareStatement(sql);
	        set(ps, 1, tokenId, Types.VARCHAR);
	        ps.executeUpdate();
	    } catch (SQLException e) {
	        throw e;
	    } finally {
	        closeStatement(ps);
	    }
	   //删除
  		try {
      		ps = con.prepareStatement("delete from "+tableName+" where token_id = ?");
      		set(ps, 1, tokenId, Types.VARCHAR);
      		ps.executeUpdate();
      	} catch (SQLException e) {
      		throw e;
      	} finally {
      		closeStatement(ps);
      		closeConnection(con);
      	}
	}
	
	/**
	 * 不验证
	 */
	@Override
	public void validateTokenConfig(WebToken webToken) {
	}
	
	/**
	 * 为token存储指定数据源
	 * @param dataSource
	 */
	public void setDataSource(DataSource dataSource) {
		this.dataSource = dataSource;
	}
	/**
	 * 可修改保存token表名，结构不能修改
	 */
	public void setTableName(String tableName) {
		this.tableName = tableName;
	}

	protected static void closeStatement(Statement stmt) {
		try {
			if (stmt != null)
				stmt.close();
		} catch (SQLException e) {
			logger.error("closeStatement", e);
		}
	}

	protected static void closeResultSet(ResultSet rs) {
		try {
			if (rs != null)
				rs.close();
		} catch (SQLException e) {
			logger.error("closeSResultSet", e);
		}
	}

	protected static void closeConnection(Connection connection) {
		try {
			if (connection != null)
				connection.close();
		} catch (Exception e) {
			logger.error("closeConnection", e);
		}
	}

	protected static void set(PreparedStatement ps, int index, Object value, int sqlType) throws SQLException {
		if (value != null) {
			ps.setObject(index, value, sqlType);
		} else {
			ps.setNull(index, sqlType);
		}
	}
}
